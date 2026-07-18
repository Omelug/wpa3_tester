#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>

#include "ex_program/hostapd/hostapd_helper.h"

using namespace std;
using namespace filesystem;
using namespace nlohmann;
using namespace wpa3_tester::hostapd;

namespace{

path write_tmp(const string &content){
	path p = temp_directory_path() / "test_wpa_overrides.conf";
	ofstream(p) << content;
	return p;
}

string read_file(const path &p){
	ifstream f(p);
	return string(istreambuf_iterator(f), {});
}

}

TEST_CASE("apply_wpa_overrides - replace global key"){
	path cfg = write_tmp(
		"ctrl_interface=/var/run/wpa_supplicant\n"
		"network={\n"
		"\tssid=\"TestNet\"\n"
		"}\n"
	);
	apply_wpa_overrides(cfg, json{{"ctrl_interface", "/tmp/new"}});
	string out = read_file(cfg);

	CHECK_EQ(out.find("ctrl_interface=/var/run/wpa_supplicant"), string::npos);
	CHECK_NE(out.find("ctrl_interface=\"/tmp/new\""), string::npos);
	remove(cfg);
}

TEST_CASE("apply_wpa_overrides - replace network key"){
	path cfg = write_tmp(
		"network={\n"
		"\tssid=\"OldNet\"\n"
		"\tkey_mgmt=WPA-PSK\n"
		"}\n"
	);
	apply_wpa_overrides(cfg, json{{"ssid", "NewNet"}});
	string out = read_file(cfg);

	CHECK_EQ(out.find("ssid=\"OldNet\""), string::npos);
	CHECK_NE(out.find("ssid=\"NewNet\""), string::npos);
	CHECK_NE(out.find("key_mgmt=WPA-PSK"), string::npos);
	remove(cfg);
}

TEST_CASE("apply_wpa_overrides - inject missing global key"){
	path cfg = write_tmp(
		"network={\n"
		"\tssid=\"TestNet\"\n"
		"}\n"
	);
	apply_wpa_overrides(cfg, json{{"okc", 1}});
	string out = read_file(cfg);

	// global keys are flushed before network={}
	auto okc_pos = out.find("okc=1");
	auto net_pos = out.find("network={");
	CHECK_NE(okc_pos, string::npos);
	CHECK_NE(net_pos, string::npos);
	CHECK_LT(okc_pos, net_pos);
	remove(cfg);
}

TEST_CASE("apply_wpa_overrides - inject missing network key"){
	path cfg = write_tmp(
		"network={\n"
		"\tssid=\"TestNet\"\n"
		"}\n"
	);
	apply_wpa_overrides(cfg, json{{"key_mgmt", "SAE"}});
	string out = read_file(cfg);

	// new key injected before closing }
	auto km_pos  = out.find("key_mgmt=SAE");
	auto brace_pos = out.rfind('}');
	CHECK_NE(km_pos, string::npos);
	CHECK(km_pos < brace_pos);
	remove(cfg);
}

TEST_CASE("apply_wpa_overrides - no network block: appends globals and new block"){
	path cfg = write_tmp("ctrl_interface=/var/run/wpa_supplicant\n");
	apply_wpa_overrides(cfg, json{{"okc", 0}, {"ssid", "Appended"}});
	string out = read_file(cfg);

	CHECK_NE(out.find("okc=0"), string::npos);
	CHECK_NE(out.find("network={"), string::npos);
	CHECK_NE(out.find("ssid=\"Appended\""), string::npos);
	remove(cfg);
}

TEST_CASE("apply_wpa_overrides - skip keys are not written"){
	path cfg = write_tmp(
		"network={\n"
		"\tssid=\"TestNet\"\n"
		"}\n"
	);
	apply_wpa_overrides(cfg, json{
		{"wpa_supplicant_path", "/some/path"},
		{"version", "2.10"},
		{"other_options", "-d"},
		{"key_mgmt", "SAE"}
	});
	string out = read_file(cfg);

	CHECK_EQ(out.find("wpa_supplicant_path"), string::npos);
	CHECK_EQ(out.find("version"), string::npos);
	CHECK_EQ(out.find("other_options"), string::npos);
	CHECK_NE(out.find("key_mgmt=SAE"), string::npos);
	remove(cfg);
}

TEST_CASE("apply_wpa_overrides - empty overrides: file unchanged"){
	const string original =
		"ctrl_interface=/var/run/wpa_supplicant\n"
		"network={\n"
		"\tssid=\"TestNet\"\n"
		"}\n";
	path cfg = write_tmp(original);
	apply_wpa_overrides(cfg, json{
		{"wpa_supplicant_path", "/some/path"},
		{"version", "2.10"}
	});
	CHECK_EQ(read_file(cfg), original);
	remove(cfg);
}

TEST_CASE("apply_wpa_overrides - CRLF line endings"){
	path cfg = write_tmp("network={\r\n\tssid=\"OldNet\"\r\n}\r\n");
	apply_wpa_overrides(cfg, json{{"ssid", "NewNet"}});
	string out = read_file(cfg);

	CHECK_EQ(out.find("ssid=\"OldNet\""), string::npos);
	CHECK_NE(out.find("ssid=\"NewNet\""), string::npos);
	remove(cfg);
}
