#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

#include "default.h"
#include "root_dir_helper.h"

#include "suite/DoS_hard/sae_dos/sae_dos_entry.h"
#include "suite/scan/ap_info_wpa3_filler.h"
#include "suite/scan/iface_info_filler.h"
#include "suite/two_iface/injection_test_filler.h"
#include "suite/DoS_soft/bl0ck/bl0ck_test_suites.h"
#include "suite/downgrade/owe_trans_filler.h"
#include "suite/Enterprise/invalid_curve/invalid_curve_filler.h"
#include "suite/two_iface/active_test_filler.h"
#include "suite/Enterprise/reflection_attack/reflection_attack_filler.h"
#include "suite/downgrade/wpa3_trans_downgrade_filler.h"
#include "suite/DoS_soft/malformed_eapol1/malformed_eapol1_suite.h"

using namespace std;
using namespace filesystem;
using json = nlohmann::json;
using namespace wpa3_tester;

namespace {

path setup_dir(string_view tag) {
    path d = temp_directory_path() / ("wpa3_ep_" + string(tag));
    remove_all(d);
    create_directories(d);
    return d;
}

void write_result(const path &d, const json &j) {
    ofstream(d / RESULT_NAME) << j.dump();
}

// actors: {name, driver, mac}
void write_mapping(const path &d, initializer_list<tuple<string, string, string>> actors) {
    ofstream f(d / "mapping.csv");
    f << "Type,ActorName,Interface,MAC,Driver,channel,json_obj\n";
    for (auto &&[name, drv, mac] : actors) {
        // sk_name(SK::driver_name) == "driver", not "driver_name"
        json j = {{"selection", {{"driver", drv}, {"mac", mac}}}, {"source", "internal"}};
        string raw = j.dump();
        string q = "\"";
        for (char c : raw) { if (c == '"') q += '"'; q += c; }
        q += '"';
        f << "internal," << name << ",wlan0," << mac << "," << drv << ",6," << q << "\n";
    }
}

void write_config(const path &d, initializer_list<string_view> actors) {
    ofstream f(d / TEST_CONFIG_NAME);
    f << "name: parse_test\nattacker_module: test_module\nactors:\n";
    for (auto a : actors) f << "  " << a << ":\n    source: internal\n";
}

} // namespace

// -----------------
TEST_CASE("SaeDosFolderEntry::parse - sets name, no png") {
    const auto d = setup_dir("sae_no_png");
    const auto e = suite::sae_dos::SaeDosFolderEntry::parse(d);
    CHECK_EQ(e.name, d.filename().string());
    CHECK(e.ap_res_png.empty());
}

TEST_CASE("SaeDosFolderEntry::parse - detects existing png") {
    const auto d = setup_dir("sae_with_png");
    const auto png = d / "observer" / "resource_checker" / "access_point_res.png";
    create_directories(png.parent_path());
    ofstream(png) << "";
    const auto e = suite::sae_dos::SaeDosFolderEntry::parse(d);
    CHECK_EQ(e.ap_res_png, png);
}

// -----------------
TEST_CASE("ApInfoWpa3TestEntry::parse - no result.json returns empty strings") {
    const auto d = setup_dir("apinfo_no_result");
    const auto e = suite::ap_info_wpa3_filler::ApInfoWpa3TestEntry::parse(d);
    CHECK_EQ(e.test_name, d.filename().string());
    CHECK(e.mac.empty());
    CHECK(e.ssid.empty());
}

TEST_CASE("ApInfoWpa3TestEntry::parse - populates from result.json") {
    const auto d = setup_dir("apinfo_with_result");
    write_result(d, {
        {"mac",           "aa:bb:cc:dd:ee:ff"},
        {"ssid",          "TestNet"},
        {"mfp",           "required"},
        {"akm",           "WPA3-SAE"},
        {"beacon_found",  true},
        {"acm_triggered", false},
        {"stations",      json::array({"11:22:33:44:55:66"})},
    });
    const auto e = suite::ap_info_wpa3_filler::ApInfoWpa3TestEntry::parse(d);
    CHECK_EQ(e.test_name, d.filename().string());
    CHECK_EQ(e.mac,  "aa:bb:cc:dd:ee:ff");
    CHECK_EQ(e.ssid, "TestNet");
    CHECK_EQ(e.mfp,  "required");
    CHECK_EQ(e.akm,  "WPA3-SAE");
    CHECK_EQ(e.beacon_found,  true);
    CHECK_EQ(e.acm_triggered, false);
    REQUIRE_EQ(e.stations.size(), 1);
    CHECK_EQ(e.stations[0], "11:22:33:44:55:66");
}

// -----------------
TEST_CASE("IfaceInfoTestEntry::parse - no config sets hw_summary to ?") {
    const auto d = setup_dir("iface_no_cfg");
    // no test_config.yaml -> early branch sets hw_summary = "?"
    const auto e = suite::iface_info_filler::IfaceInfoTestEntry::parse(d);
    CHECK_EQ(e.test_name, d.filename().string());
    CHECK_EQ(e.hw_summary, "?");
}

// -----------------
TEST_CASE("InjectionTestEntry::parse - no result.json returns zero counts") {
    const auto d = setup_dir("inject_no_result");
    // no result.json -> early return before load_test_rs
    const auto e = suite::injection_test_filler::InjectionTestEntry::parse(d);
    CHECK_EQ(e.test_name, d.filename().string());
    CHECK_EQ(e.tests_passed, 0);
    CHECK_EQ(e.tests_total, 0);
    CHECK(e.failures.empty());
    CHECK_FALSE(e.passed.has_value());
}

// -----------------
// Bl0ckTestEntry uses RunStatus default ctor (no config_validation), so no IsolatedRootDir needed.
TEST_CASE("Bl0ckTestEntry::parse - no config uses result.json only") {
    const auto d = setup_dir("bl0ck_no_cfg");
    write_result(d, {{"disconnect_count", 3}});
    const auto e = suite::bl0ck_test_suites::Bl0ckTestEntry::parse(d);
    CHECK_EQ(e.name, d.filename().string());
    CHECK_EQ(e.disconnect_count, 3);
    CHECK(e.ap_mac.empty());
}

TEST_CASE("Bl0ckTestEntry::parse - reads actors and attack_variant") {
    const auto d = setup_dir("bl0ck_full");
    write_result(d, {{"disconnect_count", 2}});
    write_mapping(d, {
        {"access_point", "ath9k",    "aa:bb:cc:00:00:01"},
        {"client",       "rt2800",   "aa:bb:cc:00:00:02"},
        {"attacker",     "ath9k_htc","aa:bb:cc:00:00:03"},
    });
    {
        ofstream f(d / TEST_CONFIG_NAME);
        f << "attack_config:\n  attack_variant: deauth_flood\n";
    }
    const auto e = suite::bl0ck_test_suites::Bl0ckTestEntry::parse(d);
    CHECK_EQ(e.name, d.filename().string());
    CHECK_EQ(e.disconnect_count, 2);
    CHECK_EQ(e.ap_mac,         "aa:bb:cc:00:00:01");
    CHECK_EQ(e.ap_source,      "internal");
    CHECK_EQ(e.client_mac,     "aa:bb:cc:00:00:02");
    CHECK_EQ(e.attacker_driver,"ath9k_htc");
    CHECK_EQ(e.attack_variant, "deauth_flood");
}

// ----- tests that call load_test_rs -> config_validation (need IsolatedRootDir) -----

TEST_CASE("OweTransTestEntry::parse - reads drivers and probe counts") {
    const test_helpers::IsolatedRootDir iso("ep_owe");
    const auto d = setup_dir("owe_full");
    write_result(d, {{"broadcast_probe_count", 5}, {"ssid_probe_count", 2}, {"disconnected", true}});
    write_config(d, {"access_point", "client", "attacker"});
    write_mapping(d, {
        {"access_point", "ath9k",   "aa:00:00:00:00:01"},
        {"client",       "rt2800",  "aa:00:00:00:00:02"},
        {"attacker",     "mt76x2u", "aa:00:00:00:00:03"},
    });
    const auto e = suite::owe_trans_filler::OweTransTestEntry::parse(d);
    CHECK_EQ(e.test_name,              d.filename().string());
    CHECK_EQ(e.ap_driver,              "ath9k");
    CHECK_EQ(e.client_driver,          "rt2800");
    CHECK_EQ(e.attacker_driver,        "mt76x2u");
    CHECK_EQ(e.broadcast_probe_count,  5);
    CHECK_EQ(e.ssid_probe_count,       2);
    CHECK_EQ(e.disconnected,           true);
}

TEST_CASE("InvalidCurveTestEntry::parse - reads drivers and passed") {
    const test_helpers::IsolatedRootDir iso("ep_invcurve");
    const auto d = setup_dir("invcurve_full");
    write_result(d, {{"passed", true}});
    write_config(d, {"access_point", "attacker"});
    write_mapping(d, {
        {"access_point", "ath9k",   "aa:00:00:00:01:01"},
        {"attacker",     "mt76x2u", "aa:00:00:00:01:02"},
    });
    const auto e = suite::invalid_curve_filler::InvalidCurveTestEntry::parse(d);
    CHECK_EQ(e.ap_driver,       "ath9k");
    CHECK_EQ(e.attacker_driver, "mt76x2u");
    REQUIRE(e.passed.has_value());
    CHECK_EQ(e.passed.value(), true);
}

TEST_CASE("ActiveTestEntry::parse - reads drivers and acked counts") {
    const test_helpers::IsolatedRootDir iso("ep_active");
    const auto d = setup_dir("active_full");
    write_result(d, {{"acked", 10}, {"not_acked", 2}, {"success", true}});
    write_config(d, {"transceiver", "receiver"});
    write_mapping(d, {
        {"transceiver", "ath9k",  "bb:00:00:00:00:01"},
        {"receiver",    "rt2800", "bb:00:00:00:00:02"},
    });
    const auto e = suite::active_test_filler::ActiveTestEntry::parse(d);
    CHECK_EQ(e.tx_driver,  "ath9k");
    CHECK_EQ(e.rx_driver,  "rt2800");
    CHECK_EQ(e.acked,      10);
    CHECK_EQ(e.not_acked,  2);
    CHECK_EQ(e.success,    true);
}

TEST_CASE("ReflectionAttackTestEntry::parse - reads drivers and passed") {
    const test_helpers::IsolatedRootDir iso("ep_refl");
    const auto d = setup_dir("refl_full");
    write_result(d, {{"passed", false}});
    write_config(d, {"access_point", "attacker"});
    write_mapping(d, {
        {"access_point", "ath9k",   "cc:00:00:00:00:01"},
        {"attacker",     "mt76x2u", "cc:00:00:00:00:02"},
    });
    const auto e = suite::reflection_attack_filler::ReflectionAttackTestEntry::parse(d);
    CHECK_EQ(e.ap_driver,       "ath9k");
    CHECK_EQ(e.attacker_driver, "mt76x2u");
    REQUIRE(e.passed.has_value());
    CHECK_EQ(e.passed.value(), false);
}

TEST_CASE("Wpa3TransDowngradeTestEntry::parse - reads drivers and downgrade_seen") {
    const test_helpers::IsolatedRootDir iso("ep_wpa3dn");
    const auto d = setup_dir("wpa3dn_full");
    write_result(d, {{"downgrade_seen", true}, {"disconnected", true}});
    write_config(d, {"access_point", "client"});
    write_mapping(d, {
        {"access_point", "ath9k",  "dd:00:00:00:00:01"},
        {"client",       "rt2800", "dd:00:00:00:00:02"},
    });
    const auto e = suite::wpa3_trans_downgrade_filler::Wpa3TransDowngradeTestEntry::parse(d);
    CHECK_EQ(e.ap_driver,      "ath9k");
    CHECK_EQ(e.client_driver,  "rt2800");
    CHECK_EQ(e.downgrade_seen, true);
    CHECK_EQ(e.disconnected,   true);
}

TEST_CASE("InjectionTestEntry::parse - counts sub-tests and records failures") {
    const test_helpers::IsolatedRootDir iso("ep_inject");
    const auto d = setup_dir("inject_full");
    write_result(d, {
        {"tests", {
            {"inject_basic", {{"result", "PASSED"}}},
            {"inject_qos",   {{"result", "PASSED"}}},
            {"inject_retry", {{"result", "FAILED"}, {"detail", "no ack"}}},
        }},
    });
    write_config(d, {"transceiver", "receiver"});
    write_mapping(d, {
        {"transceiver", "ath9k",  "ee:00:00:00:00:01"},
        {"receiver",    "rt2800", "ee:00:00:00:00:02"},
    });
    const auto e = suite::injection_test_filler::InjectionTestEntry::parse(d);
    CHECK_EQ(e.tx_driver,    "ath9k");
    CHECK_EQ(e.rx_driver,    "rt2800");
    CHECK_EQ(e.tests_total,  3);
    CHECK_EQ(e.tests_passed, 2);
    REQUIRE(e.passed.has_value());
    CHECK_EQ(e.passed.value(), false);
    REQUIRE_EQ(e.failures.size(), 1);
    CHECK_EQ(e.failures[0].first,  "inject_retry");
    CHECK_EQ(e.failures[0].second, "no ack");
}

TEST_CASE("MalformedEapol1TestEntry::parse - reads drivers and disconnect_count") {
    const test_helpers::IsolatedRootDir iso("ep_meapol");
    const auto d = setup_dir("meapol_full");
    write_result(d, {{"disconnect_count", 4}, {"rogue_ap_connected", true}});
    write_config(d, {"access_point", "client", "attacker"});
    write_mapping(d, {
        {"access_point", "ath9k",   "ff:00:00:00:00:01"},
        {"client",       "rt2800",  "ff:00:00:00:00:02"},
        {"attacker",     "mt76x2u", "ff:00:00:00:00:03"},
    });
    const auto e = suite::malformed_eapol1_filler::MalformedEapol1TestEntry::parse(d);
    CHECK_EQ(e.ap_driver,       "ath9k");
    CHECK_EQ(e.client_driver,   "rt2800");
    CHECK_EQ(e.attacker_driver, "mt76x2u");
    CHECK_EQ(e.client_version,  "default");  // no setup.program_config.version in yaml
    CHECK_EQ(e.disconnect_count, 4);
    REQUIRE(e.rogue_ap_connected.has_value());
    CHECK_EQ(e.rogue_ap_connected.value(), true);
}
