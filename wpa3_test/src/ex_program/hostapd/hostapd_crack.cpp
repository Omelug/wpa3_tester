#include <array>
#include <cstring>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#  include <openssl/core_names.h>
#else
#  include <openssl/cmac.h>
#endif
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/log.h"

namespace wpa3_tester::hostapd {
using namespace std;
using namespace filesystem;

namespace {

//TODO source (hostapd? -o r just test it more or standard )
vector<uint8_t> hex2bytes(const string &hex) {
	vector<uint8_t> r;
	r.reserve(hex.size() / 2);
	for(size_t i = 0; i + 1 < hex.size(); i += 2)
		r.push_back(static_cast<uint8_t>(stoul(hex.substr(i, 2), nullptr, 16)));
	return r;
}

struct WpaHashEntry {
	vector<uint8_t> mic; // 16 bytes
	vector<uint8_t> ap_mac;
	vector<uint8_t> sta_mac;
	vector<uint8_t> ssid;
	vector<uint8_t> anonce; // 32 bytes
	vector<uint8_t> eapol;	// EAPOL frame, MIC position zeroed
	bool is_sha256{};
	uint8_t ver{};          // key_info bits 0-2
	string raw; // original WPA*02*... line
};

// WPA*02*MIC*AP_MAC*STA_MAC*SSID_hex*ANonce*EAPOL_hex*msgpair
optional<WpaHashEntry> parse_wpa_hash(const string &line) {
	vector<string> f;
	size_t pos = 0;
	while(true) {
		const size_t sep = line.find('*', pos);
		f.push_back(line.substr(pos, sep == string::npos ? sep : sep - pos));
		if(sep == string::npos) break;
		pos = sep + 1;
	}
	if(f.size() < 9 || f[0] != "WPA" || f[1] != "02") return nullopt;

	WpaHashEntry h;
	h.mic = hex2bytes(f[2]);
	h.ap_mac = hex2bytes(f[3]);
	h.sta_mac = hex2bytes(f[4]);
	h.ssid = hex2bytes(f[5]);
	h.anonce = hex2bytes(f[6]);
	h.eapol = hex2bytes(f[7]);
	h.raw = line;

	if(h.mic.size() != 16 || h.ap_mac.size() != 6 || h.sta_mac.size() != 6 || h.anonce.size() != 32 ||
		h.eapol.size() < 99)
		return nullopt;

	// EAPOL[5:6] = key_info (big-endian); bits 0-2 = key descriptor version
	// ver 0: modern wpa_supplicant (>=2.10) for AKM 5/6 — MIC = HMAC-SHA256
	// ver 3: older wpa_supplicant (<2.10) for AKM 5/6 with CCMP — MIC = AES-128-CMAC
	// ver 2: WPA2-PSK (AKM 2) — MIC = HMAC-SHA1
	const uint16_t key_info = static_cast<uint16_t>(h.eapol[5]) << 8 | h.eapol[6];
	h.ver = key_info & 0x07;
	h.is_sha256 = h.ver == 0 || h.ver == 3;
	return h;
}

struct PtkCtx { array<uint8_t, 32> pmk{}; vector<uint8_t> ctx; vector<uint8_t> snonce; };

PtkCtx make_ptk_ctx(const WpaHashEntry &h, const string &psk) {
	PtkCtx r;
	PKCS5_PBKDF2_HMAC(psk.data(), static_cast<int>(psk.size()),
		h.ssid.data(), static_cast<int>(h.ssid.size()),
		4096, EVP_sha1(), 32, r.pmk.data());
	r.snonce = vector(h.eapol.begin() + 17, h.eapol.begin() + 49);
	r.ctx.reserve(76);
	const auto &[lo_mac, hi_mac] = h.ap_mac < h.sta_mac ? pair{h.ap_mac, h.sta_mac} : pair{h.sta_mac, h.ap_mac};
	const auto &[lo_n, hi_n] = h.anonce < r.snonce ? pair{h.anonce, r.snonce} : pair{r.snonce, h.anonce};
	r.ctx.insert(r.ctx.end(), lo_mac.begin(), lo_mac.end());
	r.ctx.insert(r.ctx.end(), hi_mac.begin(), hi_mac.end());
	r.ctx.insert(r.ctx.end(), lo_n.begin(), lo_n.end());
	r.ctx.insert(r.ctx.end(), hi_n.begin(), hi_n.end());
	return r;
}

//TODO sources from IEEE

// WPA2-PSK (AKM 2): WPA-PRF-384 (HMAC-SHA1), MIC = HMAC-SHA1(KCK, eapol)[0:16]
// PRF iter: HMAC-SHA1(pmk, label || 0x00 || ctx || i8), i=0,1,2 → 60 bytes, take 48
bool verify_sha1_mic(const WpaHashEntry &h, const string &psk) {
	const auto [pmk, ctx, snonce] = make_ptk_ctx(h, psk);
	static constexpr string_view label = "Pairwise key expansion";
	array<uint8_t, 48> ptk{};
	for(uint8_t i = 0; i < 3; ++i) {
		vector<uint8_t> msg;
		msg.reserve(label.size() + 1 + ctx.size() + 1);
		msg.insert(msg.end(), label.begin(), label.end());
		msg.push_back(0x00);
		msg.insert(msg.end(), ctx.begin(), ctx.end());
		msg.push_back(i);
		array<uint8_t, 20> mac{};
		unsigned int mac_len = 20;
		HMAC(EVP_sha1(), pmk.data(), 32, msg.data(), msg.size(), mac.data(), &mac_len);
		memcpy(ptk.data() + i * 20, mac.data(), min<size_t>(20, 48 - i * 20));
	}
	array<uint8_t, 20> computed{};
	unsigned int len = 20;
	HMAC(EVP_sha1(), ptk.data(), 16, h.eapol.data(), h.eapol.size(), computed.data(), &len);
	return memcmp(computed.data(), h.mic.data(), 16) == 0;
}

// WPA-PSK-SHA256 (AKM 6): PTK via SHA256-PRF-384, MIC = HMAC-SHA256(KCK, eapol)[0:16]
// PRF iter: HMAC-SHA256(pmk, LE16(i) || label || ctx || LE16(384)), i=1,2 → 64 bytes, take 48
// matches wpa_supplicant sha256_prf_bits: no 0x00 separator between label and context
bool verify_sha256_mic(const WpaHashEntry &h, const string &psk) {
	const auto [pmk, ctx, snonce] = make_ptk_ctx(h, psk);
	static constexpr string_view label = "Pairwise key expansion";
	array<uint8_t, 48> ptk{};
	for(uint16_t i = 1; i <= 2; ++i) {
		constexpr uint16_t ptk_bits = 384;
		vector<uint8_t> msg;
		msg.reserve(2 + label.size() + ctx.size() + 2);
		msg.push_back(i & 0xFF);
		msg.push_back(i >> 8 & 0xFF);
		msg.insert(msg.end(), label.begin(), label.end());
		msg.insert(msg.end(), ctx.begin(), ctx.end());
		msg.push_back(ptk_bits & 0xFF);
		msg.push_back(ptk_bits >> 8 & 0xFF);
		array<uint8_t, 32> mac{};
		unsigned int mac_len = 32;
		HMAC(EVP_sha256(), pmk.data(), 32, msg.data(), msg.size(), mac.data(), &mac_len);
		const size_t off = (i - 1) * 32;
		memcpy(ptk.data() + off, mac.data(), min<size_t>(32, 48 - off));
	}
	array<uint8_t, 32> tmp{};
	unsigned int len = 32;
	HMAC(EVP_sha256(), ptk.data(), 16, h.eapol.data(), h.eapol.size(), tmp.data(), &len);
	return memcmp(tmp.data(), h.mic.data(), 16) == 0;
}

}

CrackResult crack_pmk_hashes(const path &creds_file, const string &psk) {
	if(!exists(creds_file)) {
		log(LogLevel::WARNING, "wpa.creds not found: {}", creds_file);
		return { 0, 0 };
	}

	vector<WpaHashEntry> sha1_hashes, sha256_hashes;
	{
		ifstream f(creds_file);
		string line;
		while(getline(f, line)) {
			const auto tab = line.find('\t');
			const string hash_line = tab == string::npos ? line : line.substr(tab + 1);
			if(!hash_line.starts_with("WPA*")) continue;
			if(auto h = parse_wpa_hash(hash_line)) {
				if(h->is_sha256) {
					sha256_hashes.push_back(std::move(*h));
				} else {
					sha1_hashes.push_back(std::move(*h));
				}
			} else {
				log(LogLevel::ERROR, "crack_pmk_hashes: not valid format for cracking: {}...", hash_line.substr(0, 40));
			}
		}
	}

	const int total = static_cast<int>(sha1_hashes.size() + sha256_hashes.size());
	if(total == 0) return { 0, 0 };

	int cracked = 0;

	for(const auto &h: sha256_hashes)
		if(verify_sha256_mic(h, psk)) ++cracked;
	for(const auto &h: sha1_hashes)
		if(verify_sha1_mic(h, psk)) ++cracked;

	log(LogLevel::INFO,
		"cracked: {}/{} hashes ({} SHA256, {} SHA1) with password \"{}\"",
		cracked, total,
		sha256_hashes.size(), sha1_hashes.size(), psk);
	return { total, cracked };
}

}
