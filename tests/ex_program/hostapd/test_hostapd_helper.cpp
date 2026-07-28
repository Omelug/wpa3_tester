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
// ── akm_from_ap_log ─────────────────────────────────────────────────────────

TEST_CASE("akm_from_ap_log - returns SAE from AKM-defined fallback"){
    const path log = TEST_DIR / path("ap_sae_akm.log");
    REQUIRE(exists(log));
    const string akm = hostapd::akm_from_ap_log(log, {});
    CHECK_EQ(akm, "SAE");
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