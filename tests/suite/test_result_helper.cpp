#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <nlohmann/json.hpp>

#include "default.h"
#include "logger/log_util.h"
#include "overview/described.h"
#include "suite/result_helper.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester::suite::helper;
using json = nlohmann::json;
using wpa3_tester::described_bool;
using wpa3_tester::described_str;
using wpa3_tester::RunStatus;
using wpa3_tester::TimeWindow;
using wpa3_tester::LogTimePoint;

// minimal aggregate struct
struct TestEntry{
	string name{};
	[[maybe_unused]] int count{};
	[[maybe_unused]] bool flag{};
	optional<bool> opt_flag{};
	optional<string> opt_name{};
};

// writes result.json into a temp dir, returns the dir path
static path make_result_dir(const json &j){
	const path dir = temp_directory_path() / "wpa3_result_helper_test";
	create_directories(dir);
	ofstream(dir / RESULT_NAME) << j.dump();
	return dir;
}

// -----------------
TEST_CASE("load_result_default - all fields present"){
	const auto dir = make_result_dir({
		{"name", "foo"},
		{"count", 42},
		{"flag", true},
		{"opt_flag", false},
		{"opt_name", "bar"},
	});

	const auto [name, count, flag, opt_flag, opt_name] = load_result_default<TestEntry>(dir);
	CHECK_EQ(name, "foo");
	CHECK_EQ(count, 42);
	CHECK_EQ(flag, true);
	REQUIRE(opt_flag.has_value());
	CHECK_EQ(opt_flag.value(), false);
	REQUIRE(opt_name.has_value());
	CHECK_EQ(opt_name.value(), "bar");
}

TEST_CASE("load_result_default - string default is '-'"){
	const auto dir = make_result_dir({{"count", 1}});

	const auto e = load_result_default<TestEntry>(dir);
	CHECK_EQ(e.name, "-");
}

TEST_CASE("load_result_default - optional<string> default is 'N/A'"){
	const auto dir = make_result_dir({{"count", 1}});

	const auto e = load_result_default<TestEntry>(dir);
	REQUIRE(e.opt_name.has_value());
	CHECK_EQ(e.opt_name.value(), "N/A");
}

TEST_CASE("load_result_default - optional<bool> default is nullopt"){
	const auto dir = make_result_dir({{"flag", true}});

	const auto e = load_result_default<TestEntry>(dir);
	CHECK_FALSE(e.opt_flag.has_value());
}

TEST_CASE("load_result_default - no result.json returns entry_defaults"){
	const path dir = temp_directory_path() / "wpa3_no_result";
	create_directories(dir);
	remove(dir / RESULT_NAME);

	const auto [name, count, flag, opt_flag, opt_name] = load_result_default<TestEntry>(dir);
	CHECK_EQ(name, ""); // no result.json -> Entry{} not entry_default
	CHECK_EQ(count, 0);
	CHECK_EQ(flag, false);
	CHECK_FALSE(opt_flag.has_value());
	CHECK_FALSE(opt_name.has_value());
}

// ---- described_bool JSON roundtrip ----

TEST_CASE("described_bool - to_json"){
	described_bool d;
	d += {true, "source_a"};
	d += {false, "source_b"};
	const json j = d;
	REQUIRE(j.is_array());
	REQUIRE_EQ(j.size(), 2u);
	CHECK_EQ(j[0]["value"], true);
	CHECK_EQ(j[0]["description"], "source_a");
	CHECK_EQ(j[1]["value"], false);
	CHECK_EQ(j[1]["description"], "source_b");
}

TEST_CASE("described_bool - from_json roundtrip"){
	const json j = json::array({
		{{"value", false}, {"description", "conf"}},
		{{"value", nullptr}, {"description", "pcap"}},
	});
	const auto d = j.get<described_bool>();
	REQUIRE_EQ(d.pairs.size(), 2u);
	REQUIRE(d.pairs[0].value.has_value());
	CHECK_EQ(d.pairs[0].value.value(), false);
	CHECK_EQ(d.pairs[0].description, "conf");
	CHECK_FALSE(d.pairs[1].value.has_value());
	CHECK_EQ(d.pairs[1].description, "pcap");
}

// ---- described_str JSON roundtrip ----

TEST_CASE("described_str - to_json"){
	described_str d;
	d += {"SAE", "hostapd_log"};
	const json j = d;
	REQUIRE(j.is_array());
	REQUIRE_EQ(j.size(), 1u);
	CHECK_EQ(j[0]["value"], "SAE");
	CHECK_EQ(j[0]["description"], "hostapd_log");
}

TEST_CASE("described_str - from_json roundtrip"){
	const json j = json::array({
		{{"value", "SAE WPA-PSK"}, {"description", "wpa_supplicant_conf"}},
	});
	const auto d = j.get<described_str>();
	REQUIRE_EQ(d.pairs.size(), 1u);
	CHECK_EQ(d.pairs[0].value, "SAE WPA-PSK");
	CHECK_EQ(d.pairs[0].description, "wpa_supplicant_conf");
}

// ---- helpers for RunStatus-based tests ----

static void setup_test_rs(RunStatus &rs, const path &dir, const string &program = "hostapd"){
	rs.run_folder(dir);
	rs.config({{"actors", {{"ap", {{"setup", {{"program", program}}}}}}}});
}

// ---- get_run_window ----

TEST_CASE("get_run_window - parses @START and @END from combined.log"){
	const path dir = temp_directory_path() / "wpa3_run_window_test";
	create_directories(dir / "logger");
	{
		ofstream f(dir / "logger" / "combined.log");
		f << "2026-07-27T18:36:55.686217786+0200[write_log_all] @START\n";
		f << "2026-07-27T18:37:50.428471706+0200[write_log_all] @END\n";
	}
	RunStatus rs;
	rs.run_folder(dir);
	const auto w = get_run_window(rs);
	CHECK_NE(w.start_tp, LogTimePoint{});
	CHECK_NE(w.end_tp, LogTimePoint{});
	CHECK_LT(w.start_tp, w.end_tp);
	const auto diff_sec = chrono::duration_cast<chrono::seconds>(w.end_tp - w.start_tp).count();
	CHECK_LE(diff_sec, 54);
	CHECK_LE(diff_sec, 56);
}

TEST_CASE("get_conn_WPA_version - SAE from AKM-defined fallback in ap.log"){
	const path dir = temp_directory_path() / "wpa3_conn_wpa_test";

	create_directories(dir / "logger");
	{
		ofstream f(dir / "logger" / "ap.log");
		f << "2026-07-27T18:36:55.386364254+0200 [ap] [stdout] WPA: EAPOL-Key MIC using AES-CMAC (AKM-defined - SAE)\n";
		f << wpa3_tester::START_tag << "\n";
	}
	RunStatus rs;
	setup_test_rs(rs, dir);
	const TimeWindow window_START{
		LogTimePoint{}, wpa3_tester::get_tag_time(dir / "logger" / "ap.log", wpa3_tester::START_tag)
	};
	const auto result = get_conn_WPA_version(rs, window_START);
	REQUIRE_FALSE(result.empty());
	CHECK_EQ(result.value(), "00-0f-ac:8\n(WPA3)");
	CHECK_EQ(result.last().description, "hostapd");
}

TEST_CASE("get_client_mfp - OPTIONAL from wpa_supplicant.conf and RSN IE in ap.log"){
	const path dir = temp_directory_path() / "wpa3_client_mfp_test";
	create_directories(dir / "logger");
	{
		ofstream f(dir / "client_wpa_supplicant.conf");
		f << "ieee80211w=1\n";
	}
	{
		ofstream f(dir / "logger" / "ap.log");
		//  RSN caps=0x008c -> MFPC=1, MFPR=0 -> OPTIONAL
		f <<
				"2026-07-27T18:36:55.386381748+0200 [ap] [stdout] WPA: RSN IE in EAPOL-Key - hexdump(len=28): 30 1a 01 00 00 0f ac 04 01 00 00 0f ac 04 01 00 00 0f ac 08 8c 00 00 00 00 0f ac 06\n";
	}
	RunStatus rs;
	setup_test_rs(rs, dir);
	const auto result = get_client_mfp(rs, {});
	REQUIRE_EQ(result.pairs.size(), 2u);
	CHECK_EQ(result.pairs[0].value, "OPTIONAL");
	CHECK_EQ(result.pairs[0].description, "wpa_supplicant_conf");
	CHECK_EQ(result.pairs[1].value, "OPTIONAL");
	CHECK_EQ(result.pairs[1].description, "hostapd");
}

TEST_CASE("get_ap_WPA_support - reads wpa_key_mgmt from ap_hostapd.conf"){
	const path dir = temp_directory_path() / "wpa3_ap_wpa_test";
	create_directories(dir);
	{
		ofstream f(dir / "ap_hostapd.conf");
		f << "ieee80211w=2\n";
		f << "wpa_key_mgmt=SAE\n";
	}
	RunStatus rs;
	setup_test_rs(rs, dir);
	const auto result = get_ap_WPA_support(rs);
	REQUIRE_FALSE(result.empty());
	CHECK_EQ(result.value(), "SAE");
	CHECK_EQ(result.last().description, "hostapd_conf");
}

  // ---- hostapd_mana_crack tests ----

  TEST_CASE("hostapd_mana_crack - rogue_ap does not exist") {
	  const path dir = temp_directory_path() / "wpa3_mana_crack_test_no_rogue";
	  create_directories(dir);

	  RunStatus rs;
	  rs.run_folder(dir);
	  rs.config({{"actors", {{"ap", {{"setup", {{"program", "hostapd"}}}}}}}});

	  std::vector<std::unique_ptr<wpa3_tester::GraphElements>> elements;

	  const auto result = hostapd_mana_crack(rs, elements);

	  REQUIRE_FALSE(result.first.has_value());
	  REQUIRE_FALSE(result.second.has_value());
  }

  // ---- get_ap_ocv tests ----

  TEST_CASE("get_ap_ocv - from hostapd_conf") {
	  const path dir = temp_directory_path() / "wpa3_ap_ocv_test";
	  create_directories(dir);

	  // ap_hostapd.conf with okc value
	  ofstream f(dir / "ap_hostapd.conf");
	  f << "okc=1\n";
	  f.close();

	  RunStatus rs;
	  rs.run_folder(dir);
	  rs.config({{"actors", {{"ap", {{"setup", {{"program", "hostapd"}}}}}}}});

	  const auto result = get_ap_ocv(rs);
	  REQUIRE_FALSE(result.empty());
	  CHECK_EQ(result.value(), true);
	  CHECK_EQ(result.last().description, "hostapd_conf");
  }

  TEST_CASE("get_ap_ocv - from pcap") {
	  const path dir = temp_directory_path() / "wpa3_ap_ocv_pcap_test";
	  create_directories(dir);
	  create_directories(dir / "tshark");

	  // Create tshark folder with pcap file
	  ofstream f(dir / "tshark" / "attacker_capture.pcap");
	  f << "fake pcap data";
	  f.close();

	  RunStatus rs;
	  rs.run_folder(dir);
	  rs.config({{"actors", {{"attacker", {{"setup", {{"program", "hostapd"}}}}}}}});

	  const auto result = get_ap_ocv(rs);

	  // Verify that the function handled the pcap case correctly
	  // (We can't easily test the actual pcap parsing without a real pcap file)
	  REQUIRE_FALSE(result.empty());
  }

  // ---- get_client_scanning tests ----

  TEST_CASE("get_client_scanning - from attacker pcap") {
	  const path dir = temp_directory_path() / "wpa3_client_scanning_test";
	  create_directories(dir);
	  create_directories(dir / "tshark");

	  // Create tshark folder with pcap file
	  ofstream f(dir / "tshark" / "attacker_capture.pcap");
	  f << "fake pcap data";
	  f.close();

	  // Create ap.log with client scanning info
	  create_directories(dir / "logger");
	  ofstream log_f(dir / "logger" / "ap.log");
	  log_f << "Client scanning info\n";
	  log_f.close();

	  RunStatus rs;
	  rs.run_folder(dir);
	  rs.config({"actors", {{"client", {{"setup", {{"program", "hostapd"}}}},
							  {"attacker", {{"setup", {{"program", "hostapd"}}}}}}}});

	  const auto result = get_client_scanning(rs, {});

	  // Verify that the function handled the pcap case correctly
	  REQUIRE_FALSE(result.empty());
  }

  TEST_CASE("get_client_scanning - from ap log") {
	  const path dir = temp_directory_path() / "wpa3_client_scanning_ap_test";
	  create_directories(dir);
	  create_directories(dir / "logger");

	  // Create ap.log with client scanning info
	  ofstream f(dir / "logger" / "ap.log");
	  f << "Channel 6\n";
	  f.close();

	  RunStatus rs;
	  rs.run_folder(dir);
	  rs.config({"actors", {{"client", {{"setup", {{"program", "hostapd"}}}},
							  {"attacker", {{"setup", {{"program", "hostapd"}}}}}}}});

	  const auto result = get_client_scanning(rs, {});
	  REQUIRE_FALSE(result.empty());
  }

  // ---- get_client_WPA_support tests ----

  TEST_CASE("get_client_WPA_support - from wpa_supplicant_conf") {
	  const path dir = temp_directory_path() / "wpa3_client_wpa_supp_test";
	  create_directories(dir);

	  ofstream f(dir / "client_wpa_supplicant.conf");
	  f << "key_mgmt=WPA-PSK\n";
	  f.close();

	  RunStatus rs;
	  rs.run_folder(dir);
	  rs.config({{"actors", {{"ap", {{"setup", {{"program", "hostapd"}}}}}}}});

	  const auto result = get_client_WPA_support(rs, {});

	  REQUIRE_FALSE(result.empty());
	  CHECK_EQ(result.value(), "WPA-PSK");
	  CHECK_EQ(result.last().description, "wpa_supplicant_conf");
  }

  /* TODO can I get info from AKM-defined message (bad info from multiple connections?)
   *TEST_CASE("get_client_WPA_support - from hostapd log") {
	  const path dir = temp_directory_path() / "wpa3_client_wpa_hostapd_test";
	  create_directories(dir);
	  create_directories(dir / "logger");

	  // ap.log with client WPA support info
	  ofstream f(dir / "logger" / "ap.log");
	  f << "WPA: EAPOL-Key MIC using AES-CMAC (AKM-defined - SAE)\n";
	  f.close();

	  RunStatus rs;
	  rs.run_folder(dir);
	  rs.config({{"actors", {{"ap", {{"setup", {{"program", "hostapd"}}}}}}}});

	  const auto result = get_client_WPA_support(rs, {});
	REQUIRE_FALSE(result.empty());
  }*/

  // ---- get_client_disconnected tests ----

  TEST_CASE("get_client_disconnected - WB client with log") {
	  const path dir = temp_directory_path() / "wpa3_client_disconnect_wb_test";
	  create_directories(dir);
	  create_directories(dir / "logger");

	  ofstream f(dir / "logger" / "client.log");
	  f << "CTRL-EVENT-DISCONNECTED\n";
	  f.close();

	  RunStatus rs;
	  rs.run_folder(dir);
	  rs.config({{"actors", {{"client", {{"setup", {{"program", "hostapd"}}}}}}}});

	  auto& client_actor = rs.get_actor("client");
	  client_actor->set(wpa3_tester::SK::source, "internal");
	const auto result = get_client_disconnected(rs, {});

	  REQUIRE_FALSE(result.empty());
	  CHECK_EQ(result.value(), true);
	  CHECK_EQ(result.last().description, "log");
  }

  TEST_CASE("get_client_disconnected - non-WB client with pcap") {
	  const path dir = temp_directory_path() / "wpa3_client_disconnect_pcap_test";
	  create_directories(dir);
	  create_directories(dir / "tshark");

		ofstream f(dir / "tshark" / "attacker_capture.pcap");
	  f << "fake pcap data";
	  f.close();

	  RunStatus rs;
	  rs.run_folder(dir);
	  rs.config({{"actors", {{"client", {{"setup", {{"program", "hostapd"}}}}}},
				  {"attacker", {{"setup", {{"program", "hostapd"}}}}}}});

	  const auto result = get_client_disconnected(rs, {});
	REQUIRE_FALSE(result.empty());
  }

