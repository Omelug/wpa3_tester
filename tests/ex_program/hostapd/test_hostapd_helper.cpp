#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

#include "config/global_config.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester;

static const path TEST_DIR = TEST_DATA_DIR;

//FIXME not working on raspberry if not installed hostapd
/*TEST_CASE("get_hostapd - empty version returns system default"){
    string result = hostapd::get_hostapd("");
    CHECK_EQ(result, "hostapd");
}*/

TEST_CASE("get_hostapd - returns existing binary if found"){
    path test_folder = temp_directory_path() / "hostapd_test_existing";
    remove_all(test_folder);
    create_directories(test_folder);

    path mock_binary = test_folder / "hostapd_2_10";
    ofstream(mock_binary) << "mock binary";

    get_global_config()["paths"]["hostapd"]["hostapd_build_folder"] = test_folder.string();
    string result = hostapd::get_hostapd("2.10");

    CHECK_EQ(result, mock_binary.string());
    CHECK(exists(mock_binary));
    remove_all(test_folder);
}

TEST_CASE("get_hostapd - throws when binary doesn't exist and repo not available"*doctest::skip (true)){
    path test_folder = temp_directory_path() / "hostapd_test_nonexistent";
    remove_all(test_folder);

    get_global_config()["paths"]["hostapd"]["hostapd_build_folder"] = test_folder.string();

    string result2_10 = hostapd::get_hostapd("2.10");
    CHECK_EQ((test_folder/ "hostapd_2_10").string(), result2_10);
    CHECK(exists(result2_10));

    string result2_9 = hostapd::get_hostapd("2.9");
    CHECK_EQ((test_folder/ "hostapd_2_9").string(), result2_9);
    CHECK(exists(result2_9));

    MESSAGE(hw_capabilities::run_cmd_output({"ls", test_folder.string()}, nullopt));

    remove_all(test_folder);
}

// ── hccapx_to_wpa_hashes ────────────────────────────────────────────────────
//TODO refactor stess (tests passs bet format helper not )
/*TEST_CASE("hccapx_to_wpa_hashes - missing file returns empty"){
    const auto result = hostapd::hccapx_to_wpa_hashes("/nonexistent/path.hccapx");
    CHECK(result.empty());
}

TEST_CASE("hccapx_to_wpa_hashes - parses mana_handshakes.hccapx"){
    const path hccapx = TEST_DIR / "mana_handshakes.hccapx";
    REQUIRE(exists(hccapx));

    const auto hashes = hostapd::hccapx_to_wpa_hashes(hccapx);

    REQUIRE_FALSE(hashes.empty());
    for(const auto &h : hashes){
        CHECK(h.starts_with("WPA*02*"));
        // format: WPA*02*<mic16B>*<ap_mac6B>*<sta_mac6B>*<ssid>*<anonce32B>*<eapol>*<pair>
        const auto fields = [&]{
            vector<string> f;
            stringstream ss(h);
            string tok;
            while(getline(ss, tok, '*')) f.push_back(tok);
            return f;
        }();
        // WPA * 02 * mic * mac_ap * mac_sta * ssid * anonce * eapol * pair = 9 parts
        CHECK_EQ(fields.size(), 9);
        CHECK_EQ(fields[0], "WPA");
        CHECK_EQ(fields[1], "02");
        CHECK_EQ(fields[2].size(), 32);   // MIC: 16 bytes hex
        CHECK_EQ(fields[3].size(), 12);   // AP MAC: 6 bytes hex
        CHECK_EQ(fields[4].size(), 12);   // STA MAC: 6 bytes hex
        CHECK_FALSE(fields[5].empty());   // SSID hex
        CHECK_EQ(fields[6].size(), 64);   // ANonce: 32 bytes hex
        CHECK_FALSE(fields[7].empty());   // EAPOL
    }
}

TEST_CASE("hccapx_to_wpa_hashes - SSID is test_channel_switch"){
    const path hccapx = TEST_DIR / "mana_handshakes.hccapx";
    REQUIRE(exists(hccapx));

    const auto hashes = hostapd::hccapx_to_wpa_hashes(hccapx);
    REQUIRE_FALSE(hashes.empty());

    // SSID "test_channel_switch" hex = 746573745f6368616e6e656c5f7377697463h
    const string expected_ssid_hex = "746573745f6368616e6e656c5f737769746368";
    for(const auto &h : hashes){
        // field[5] is ssid
        size_t pos = 0, cnt = 0;
        while(cnt < 5 && (pos = h.find('*', pos)) != string::npos){ ++pos; ++cnt; }
        const size_t end = h.find('*', pos);
        CHECK_EQ(h.substr(pos, end - pos), expected_ssid_hex);
    }
}

// ── crac c k_pmk_hashes ────────────────────────────────────────────────────────

TEST_CASE("crack_pmk_hashes - missing file returns zero"){
    const auto r = hostapd::crack_pmk_hashes("/nonexistent/captured_hashes.txt", "anypassword");
    CHECK_EQ(r.total, 0);
    CHECK_EQ(r.cracked, 0);
}

TEST_CASE("crack_pmk_hashes - wrong PSK cracks nothing"
    * doctest::skip(hw_capabilities::run_cmd({"hcxpmktool", "--version"}, nullopt, false) != 0)
){
    const path hccapx = TEST_DIR / "mana_handshakes.hccapx";
    REQUIRE(exists(hccapx));

    const auto hashes = hostapd::hccapx_to_wpa_hashes(hccapx);
    REQUIRE_FALSE(hashes.empty());

    const path tmp = temp_directory_path() / "test_captured_hashes.txt";
    { ofstream f(tmp); for(const auto &h : hashes) f << h << "\n"; }

    const auto r = hostapd::crack_pmk_hashes(tmp, "definitelyWrongPassword123!");
    CHECK_EQ(r.cracked, 0);
    CHECK_EQ(r.total, static_cast<int>(hashes.size()));

    remove(tmp);
}

TEST_CASE("crack_pmk_hashes - cracks all hashes"
    * doctest::skip(hw_capabilities::run_cmd({"hcxpmktool", "--version"}, nullopt, false) != 0)
){
    const path hashes_file = TEST_DIR / "captured_hashes.txt";
    const auto r = hostapd::crack_pmk_hashes(hashes_file, "password123");
    CHECK_EQ(r.cracked, r.total);
}
*/
// ------- akm_from_ap_log

TEST_CASE("akm_from_ap_log - returns SAE from AKM-defined fallback"){
    const path log = TEST_DIR / "ap_sae_akm.log";
    REQUIRE(exists(log));
    const string akm = hostapd::akm_from_ap_log(log, {});
    CHECK_EQ(akm, "SAE");
}

// ------- get_conf_value

TEST_CASE("get_conf_value - returns value for matching key"){
    const path tmp = temp_directory_path() / "wpa3_test_conf.conf";
    { ofstream f(tmp); f << "ssid=MyNetwork\nwpa_key_mgmt=SAE\n"; }
    CHECK_EQ(hostapd::get_conf_value(tmp, {"ssid"}), "MyNetwork");
    CHECK_EQ(hostapd::get_conf_value(tmp, {"wpa_key_mgmt"}), "SAE");
    remove(tmp);
}

TEST_CASE("get_conf_value - strips surrounding double quotes"){
    const path tmp = temp_directory_path() / "wpa3_test_conf_quoted.conf";
    { ofstream f(tmp); f << "sae_password=\"secret123\"\n"; }
    CHECK_EQ(hostapd::get_conf_value(tmp, {"sae_password"}), "secret123");
    remove(tmp);
}

TEST_CASE("get_conf_value - falls back to second key when first is absent"){
    const path tmp = temp_directory_path() / "wpa3_test_conf_fallback.conf";
    { ofstream f(tmp); f << "psk=passphrase\n"; }
    CHECK_EQ(hostapd::get_conf_value(tmp, {"sae_password", "psk"}), "passphrase");
    remove(tmp);
}

TEST_CASE("get_conf_value - ignores leading whitespace on lines"){
    const path tmp = temp_directory_path() / "wpa3_test_conf_indent.conf";
    { ofstream f(tmp); f << "  channel=6\n"; }
    CHECK_EQ(hostapd::get_conf_value(tmp, {"channel"}), "6");
    remove(tmp);
}

TEST_CASE("get_conf_value - returns empty when key not found"){
    const path tmp = temp_directory_path() / "wpa3_test_conf_missing.conf";
    { ofstream f(tmp); f << "ssid=test\n"; }
    CHECK_EQ(hostapd::get_conf_value(tmp, {"nonexistent_key"}), "");
    remove(tmp);
}

TEST_CASE("get_conf_value - returns empty for missing file"){
    CHECK_EQ(hostapd::get_conf_value("/tmp/wpa3_nonexistent.conf", {"ssid"}), "");
}

// ------- client_akm_from_ap_log

TEST_CASE("client_akm_from_ap_log - returns SAE from RSN IE in 4-Way Handshake log"){
    const path tmp = temp_directory_path() / "wpa3_test_client_akm.log";
    {
        ofstream f(tmp);
        f << "2026-07-29T01:24:34.109715456+0200 [ap] [stdout] WPA: KEK - hexdump(len=16): [REMOVED]\n"
          << "2026-07-29T01:24:34.109737104+0200 [ap] [stdout] WPA: TK - hexdump(len=16): [REMOVED]\n"
          << "2026-07-29T01:24:34.109758827+0200 [ap] [stdout] WPA: EAPOL-Key MIC using AES-CMAC (AKM-defined - SAE)\n"
          << "2026-07-29T01:24:34.109780715+0200 [ap] [stdout] WPA: RSN IE in EAPOL-Key - hexdump(len=28): 30 1a 01 00 00 0f ac 04 01 00 00 0f ac 04 01 00 00 0f ac 08 cc 00 00 00 00 0f ac 06\n"
          << "2026-07-29T01:24:34.109802641+0200 [ap] [stdout] WPA: 00:c0:ca:b5:e1:58 WPA_PTK entering state PTKCALCNEGOTIATING2\n"
          << "2026-07-29T01:24:34.109824382+0200 [ap] [stdout] WPA: 00:c0:ca:b5:e1:58 WPA_PTK entering state PTKINITNEGOTIATING\n"
          << "2026-07-29T01:24:34.109846123+0200 [ap] [stdout] wlan3: STA 00:c0:ca:b5:e1:58 WPA: sending 3/4 msg of 4-Way Handshake\n";
    }
    const string akm = hostapd::client_akm_from_ap_log(tmp);
    remove(tmp);
    CHECK_EQ(akm, "SAE");
}

TEST_CASE("client_akm_from_ap_log - returns empty for missing file"){
    const string akm = hostapd::client_akm_from_ap_log("/tmp/wpa3_nonexistent_client_akm.log");
    CHECK_EQ(akm, "");
}

// ------- client_scanning_from_ap_log

TEST_CASE("client_scanning_from_ap_log - extracts scanned channels from DS Params mismatch lines"){
    const path tmp = temp_directory_path() / "wpa3_test_scanning.log";
    {
        ofstream f(tmp);
        // probe 1: next line is send_mlme (no DS mismatch) → falls back to freq=2437 → ch 6
        // probe 2: next line is DS mismatch ds.chan=7 → ch 7
        f << "@START\n"
          << "2026-07-29T01:24:46.213618042+0200 [ap] [stdout] Ignore Probe Request due to DS Params mismatch: chan=6 != ds.chan=5\n"
          << "2026-07-29T01:24:46.281390097+0200 [ap] [stdout] nl80211: BSS Event 59 (NL80211_CMD_FRAME) received for wlan3\n"
          << "2026-07-29T01:24:46.281541486+0200 [ap] [stdout] nl80211: RX frame da=ff:ff:ff:ff:ff:ff sa=00:c0:ca:b5:e1:58 bssid=ff:ff:ff:ff:ff:ff freq=2437 ssi_signal=-81 fc=0x40 seq_ctrl=0x50 stype=4 (WLAN_FC_STYPE_PROBE_REQ) len=212\n"
          << "2026-07-29T01:24:46.281651079+0200 [ap] [stdout] nl80211: send_mlme - da=00:c0:ca:b5:e1:58 sa=24:ec:99:bf:c7:cf bssid=24:ec:99:bf:c7:cf noack=1 freq=0 no_cck=0 offchanok=0 wait_time=0 no_encrypt=0 fc=0x50 (WLAN_FC_STYPE_PROBE_RESP) nlmode=3\n"
          << "2026-07-29T01:24:46.281721671+0200 [ap] [stdout] nl80211: send_mlme - Use bss->freq=2437\n"
          << "2026-07-29T01:24:46.281788227+0200 [ap] [stdout] nl80211: send_mlme -> send_frame_cmd\n"
          << "2026-07-29T01:24:46.310374356+0200 [ap] [stdout] MGMT: Invalid SA=24:ec:99:bf:c7:cf in received frame - ignore this frame silently\n"
          << "2026-07-29T01:24:46.349436616+0200 [ap] [stdout] nl80211: BSS Event 59 (NL80211_CMD_FRAME) received for wlan3\n"
          << "2026-07-29T01:24:46.349580930+0200 [ap] [stdout] nl80211: RX frame da=ff:ff:ff:ff:ff:ff sa=00:c0:ca:b5:e1:58 bssid=ff:ff:ff:ff:ff:ff freq=2437 ssi_signal=-83 fc=0x40 seq_ctrl=0x60 stype=4 (WLAN_FC_STYPE_PROBE_REQ) len=212\n"
          << "2026-07-29T01:24:46.349650504+0200 [ap] [stdout] Ignore Probe Request due to DS Params mismatch: chan=6 != ds.chan=7\n"
          << "@END\n";
    }
    const string result = hostapd::client_scanning_from_ap_log(tmp, "00:c0:ca:b5:e1:58");
    remove(tmp);
    CHECK_EQ(result, "ch: 6 7");
}

TEST_CASE("client_scanning_from_ap_log - returns empty when no START_tag in log"){
    const path tmp = temp_directory_path() / "wpa3_test_scanning_nostart.log";
    {
        ofstream f(tmp);
        f << "nl80211: RX frame sa=00:c0:ca:b5:e1:58 freq=2437 (WLAN_FC_STYPE_PROBE_REQ)\n"
          << "Ignore Probe Request due to DS Params mismatch: chan=6 != ds.chan=11\n";
    }
    const string result = hostapd::client_scanning_from_ap_log(tmp, "00:c0:ca:b5:e1:58");
    remove(tmp);
    CHECK_EQ(result, "");
}

TEST_CASE("client_scanning_from_ap_log - returns empty for missing file"){
    CHECK_EQ(hostapd::client_scanning_from_ap_log("/tmp/wpa3_nonexistent_scan.log", "00:c0:ca:b5:e1:58"), "");
}

TEST_CASE("client_scanning_from_ap_log - returns empty when client MAC not in log"){
    const path tmp = temp_directory_path() / "wpa3_test_scanning_nomac.log";
    {
        ofstream f(tmp);
        f << "@START\n"
          << "nl80211: RX frame sa=aa:bb:cc:dd:ee:ff freq=2437 (WLAN_FC_STYPE_PROBE_REQ)\n"
          << "Ignore Probe Request due to DS Params mismatch: chan=6 != ds.chan=11\n"
          << "@END\n";
    }
    const string result = hostapd::client_scanning_from_ap_log(tmp, "00:c0:ca:b5:e1:58");
    remove(tmp);
    CHECK_EQ(result, "");
}

/*TEST_CASE("crack_pmk_hashes - correct PSK cracks all hashes"
	* doctest::skip(hw_capabilities::run_cmd({"hcxpmktool", "--version"}, nullopt, false) != 0)
){
	const path hccapx = TEST_DIR / "mana_handshakes.hccapx";
	REQUIRE(exists(hccapx));

	const auto hashes = hostapd::hccapx_to_wpa_hashes(hccapx);
	REQUIRE_FALSE(hashes.empty());

	const path tmp = temp_directory_path() / "captured_hashes.txt";
	{ ofstream f(tmp); for(const auto &h : hashes) f << h << "\n"; }

	const auto r = hostapd::crack_pmk_hashes(tmp, "password123");
	CHECK_EQ(r.total, static_cast<int>(hashes.size()));
	CHECK_EQ(r.cracked, r.total);

	remove(tmp);
}*/