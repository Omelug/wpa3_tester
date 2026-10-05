#include <array>
#include <cstring>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

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
	// wpa_supplicant sets 3 (WPA_KEY_INFO_TYPE_AES_128_CMAC) for AKM 5/6 (HMAC-SHA256 MIC)
	// version 2 -> WPA2-PSK: HMAC-SHA1 MIC
	const uint16_t key_info = static_cast<uint16_t>(h.eapol[5]) << 8 | h.eapol[6];
	h.is_sha256 = (key_info & 0x07) == 3;
	return h;
}

// Verify WPA-PSK-SHA256 (AKM 6) MIC.
// PMK  = PBKDF2-SHA1(psk, ssid, 4096, 32)
// PTK  = sha256_prf(PMK, "Pairwise key expansion",
//            min/max(MACs) || min/max(nonces), 384 bits)
//        where each PRF iteration:
//            HMAC-SHA256(k, LE16(i) || label || data || LE16(384))
// KCK  = PTK[0:16]
// MIC  = HMAC-SHA256(KCK, eapol_with_zeroed_mic)[0:16]
bool verify_sha256_mic(const WpaHashEntry &h, const string &psk) {
	array<uint8_t, 32> pmk{};
	PKCS5_PBKDF2_HMAC(psk.data(),
		static_cast<int>(psk.size()),
		h.ssid.data(),
		static_cast<int>(h.ssid.size()),
		4096,
		EVP_sha1(),
		32,
		pmk.data());

	const vector snonce(h.eapol.begin() + 17, h.eapol.begin() + 49);

	vector<uint8_t> ctx;
	ctx.reserve(76);
	const auto &[lo_mac, hi_mac] = h.ap_mac < h.sta_mac ? pair{ h.ap_mac, h.sta_mac } : pair{ h.sta_mac, h.ap_mac };
	const auto &[lo_n, hi_n] = h.anonce < snonce ? pair{ h.anonce, snonce } : pair{ snonce, h.anonce };
	ctx.insert(ctx.end(), lo_mac.begin(), lo_mac.end());
	ctx.insert(ctx.end(), hi_mac.begin(), hi_mac.end());
	ctx.insert(ctx.end(), lo_n.begin(), lo_n.end());
	ctx.insert(ctx.end(), hi_n.begin(), hi_n.end());

	static constexpr string_view label = "Pairwise key expansion";

	array<uint8_t, 48> ptk{};
	for(uint16_t i = 1; i <= 2; ++i) {
		constexpr uint16_t ptk_bits = 384;
		vector<uint8_t> msg;
		msg.reserve(2 + label.size() + ctx.size() + 2);
		msg.push_back(i & 0xFF);
		msg.push_back((i >> 8) & 0xFF);
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

	array<uint8_t, 32> computed{};
	unsigned int len = 32;
	HMAC(EVP_sha256(), ptk.data(), 16, h.eapol.data(), h.eapol.size(), computed.data(), &len);
	return memcmp(computed.data(), h.mic.data(), 16) == 0;
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

	if(!sha1_hashes.empty()) {
		if(hw_capabilities::run_cmd({ "which", "hcxpmktool" }, nullopt, false) != 0) {
			log(LogLevel::WARNING, "hcxpmktool not found, skipping {} SHA1 hash(es)", sha1_hashes.size());
		} else {
			log(LogLevel::INFO,
				"hcxpmktool: {}",
				hw_capabilities::run_cmd_output({ "hcxpmktool", "--version" }, nullopt));
			const path tmp = temp_directory_path() / "wpa3_tester_sha1.txt";
			{
				ofstream f(tmp);
				for(const auto &h2: sha1_hashes) f << h2.raw << "\n";
			}
			const string out = hw_capabilities::run_cmd_output({ "hcxpmktool", "-z", tmp.string(), "-p", psk });
			remove(tmp);
			cracked += static_cast<int>(ranges::count(out, '\n'));
		}
	}

	log(LogLevel::INFO,
		"cracked: {}/{} hashes ({} SHA256, {} SHA1)",
		cracked, total,
		sha256_hashes.size(), sha1_hashes.size());
	return { total, cracked };
}

}
