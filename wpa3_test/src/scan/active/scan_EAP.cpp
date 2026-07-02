#include <chrono>
#include <map>
#include <set>
#include <sys/poll.h>
#include <tins/rawpdu.h>

#include "attacks/components/sniffer_helper.h"
#include "attacks/Enterprise/eap_defs.h"
#include "logger/log.h"

using namespace std;
using namespace chrono;
using namespace Tins;

namespace wpa3_tester::scan{
using namespace wpa3_tester::eap;

struct EAP_Info{
	uint8_t code = 0;
	optional<string> identity;
	optional<string> method;
	uint8_t type_code = 0;
};

enum class AuthStatus{
	UNKNOWN,
	IN_PROGRESS,
	SUCCESS,
	FAILED
};

struct EAP_Session{
	set<string> identities;
	set<string> methods;
	AuthStatus status = AuthStatus::UNKNOWN;
	uint8_t last_type_code = 0;
	steady_clock::time_point last_seen;

	string to_str() const;
};

string EAP_Session::to_str() const{
	stringstream ss;
	ss << "IDs: ";
	for(auto const &id: identities) ss << id << " ";
	ss << "| Methods: ";
	for(auto const &m: methods) ss << m << " ";
	return ss.str();
}

string extract_identity(const vector<uint8_t> &payload){
	if(payload.size() <= 5) return "Empty"; // (Code, ID, LenH, LenL, Type, [Data...])
	return {payload.begin() + 5, payload.end()};
}

EAP_Info parse_eap_packet(const RawPDU &raw){
	const auto &payload = raw.payload();
	EAP_Info info;

	if(payload.size() < 5) return info;

	info.code = payload[0];

	// Success/Failure has no other info
	if(info.code == CODE_SUCCESS || info.code == CODE_FAILURE){ return info; }

	const uint8_t type = payload[4];
	info.type_code = type;

	static const map<uint8_t,string> method_names = {
		{TYPE_MD5, "EAP-MD5"}, {TYPE_GTC, "EAP-GTC"}, {TYPE_TLS, "EAP-TLS"}, {TYPE_LEAP, "EAP-LEAP"},
		{TYPE_SIM, "EAP-SIM"}, {TYPE_TTLS, "EAP-TTLS"}, {TYPE_AKA, "EAP-AKA"}, {TYPE_PEAP, "EAP-PEAP"},
		{TYPE_MSCHAPV2, "EAP-MSCHAPv2"}, {TYPE_POTP, "EAP-POTP"}, {TYPE_FAST, "EAP-FAST"}, {TYPE_EKE, "EAP-EKE"},
		{TYPE_TEAP, "EAP-TEAP"}, {TYPE_AKA_PRIME, "EAP-AKA-PRIME"}, {TYPE_PWD, "EAP-PWD"},
		{TYPE_EXPANDED, "Expanded-Type"},
	};

	if(type == TYPE_IDENTITY){
		info.identity = extract_identity(payload);
	} else if(const auto it = method_names.find(type); it != method_names.end()){
		info.method = it->second;
	} else{
		info.method = "Unknown-" + to_string(type);
	}

	if(type == TYPE_EXPANDED && payload.size() >= 12){
		// bytes 5-7: Vendor-Id
		// bytes 8-11: Vendor-Type
		info.method = "Expanded-Method (Vendor: " + to_string(payload[5]) + ")";
	}
	return info;
}

static optional<monostate> handle_eap_pdu(PDU &pdu, const HWAddress<6> &target_ap_mac,
										map<HWAddress<6>,EAP_Session> &sessions
){
	const auto *dot11_data = pdu.find_pdu<Dot11Data>();
	const auto *raw = pdu.find_pdu<RawPDU>();
	if(!dot11_data || !raw) return nullopt;

	const HWAddress<6> client_mac =
		(dot11_data->addr1() == target_ap_mac) ? dot11_data->addr2() : dot11_data->addr1();

	const EAP_Info info = parse_eap_packet(*raw);

	auto &session = sessions[client_mac];
	session.last_seen = steady_clock::now();
	session.last_type_code = info.type_code;

	if(info.identity && session.identities.insert(*info.identity).second) log(
		LogLevel::INFO, "[*] New Identity for {}: {}", client_mac, *info.identity);

	if(info.method && session.methods.insert(*info.method).second) log(LogLevel::INFO, "[+] New Method for {}: {}",
																		client_mac, *info.method);

	switch(info.code){
	case CODE_REQUEST:
	case CODE_RESPONSE: if(session.status == AuthStatus::UNKNOWN) session.status = AuthStatus::IN_PROGRESS;
		break;
	case CODE_SUCCESS: if(session.status != AuthStatus::SUCCESS){
			session.status = AuthStatus::SUCCESS;
			log(LogLevel::INFO, "[OK] Auth SUCCESS: Client {} is now CONNECTED.", client_mac);
		}
		break;
	case CODE_FAILURE: if(session.status != AuthStatus::FAILED){
			session.status = AuthStatus::FAILED;
			log(LogLevel::INFO, "[!] Auth FAILURE: Client {} was REJECTED.", client_mac);
		}
		break;
	default: throw run_err("Unknown EAP code: " + to_string(info.code));
	}

	return nullopt; // until timeout
}

void active_eap_identity_scan(const string &iface, const string &target_ap_mac, const int timeout_sec){
	map<HWAddress<6>,EAP_Session> sessions;
	components::poll_sniffer_pdu<monostate>([&](PDU &pdu){ return handle_eap_pdu(pdu, target_ap_mac, sessions); },
											iface, "", seconds(timeout_sec));
}
}