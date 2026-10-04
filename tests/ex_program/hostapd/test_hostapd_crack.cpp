#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <string>

#include "ex_program/hostapd/hostapd_helper.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester;

// Real captures from test_wpa3_tester network, password "password123".
// key_info 0x010a → version bits = 2 (WPA2-PSK, HMAC-SHA1 MIC)
static const string SHA1_HASH =
	"WPA*02"
	"*8da6894cd5ddb2d1214109ea409879e5"
	"*24ec99bfc7cf"
	"*302432f78348"
	"*746573745f777061335f746573746572"
	"*ed330d304a8efe7f12de0a249ac6d202da0f900c82249205bf5afa74bd2b6cf2"
	"*0103008702010a000000000000000000038109e05217f8cdd2d8d18a9fde804e206a95ca59561b8dc17df4bec2ded741e5000000000000000"
	"000000000000000000000000000000000000000000000000000000000000000000000000000000000002830260100000fac040100000fac040"
	"100000fac028000010047c84c3e04bbeddfd7215ad84f489d73"
	"*00";

// key_info 0x010b → version bits = 3 (WPA-PSK-SHA256, HMAC-SHA256 MIC)
static const string SHA256_HASH =
	"WPA*02"
	"*74b6914bde1ae5727031af130fde91eb"
	"*24ec99bfc7cf"
	"*302432f78348"
	"*746573745f777061335f746573746572"
	"*578e00f07bc44362cad3d0e0ef3c42fcfc7e3279d6ab6d2fd94ab60a910b8c18"
	"*0103008b02010b00000000000000000001fb0235cb5f11af19cfe06d5d3f152b0b170aae911656ffeeaa5484b3cfc603b7000000000000000"
	"000000000000000000000000000000000000000000000000000000000000000000000000000000000002c302a0100000fac040100000fac040"
	"100000fac068000010025395e35f494edf21be119f0128f8a57000fac06"
	"*00";

TEST_CASE("crack_pmk_hashes - missing file returns zero") {
	const auto r = hostapd::crack_pmk_hashes("/nonexistent/captured_hashes.txt", "anypassword");
	CHECK_EQ(r.total, 0);
	CHECK_EQ(r.cracked, 0);
}

TEST_CASE("crack_pmk_hashes - empty file returns zero") {
	const path tmp = temp_directory_path() / "wpa3_crack_empty.txt";
	ofstream{ tmp };
	const auto r = hostapd::crack_pmk_hashes(tmp, "anypassword");
	CHECK_EQ(r.total, 0);
	CHECK_EQ(r.cracked, 0);
	remove(tmp);
}

TEST_CASE("crack_pmk_hashes - invalid format lines are skipped") {
	const path tmp = temp_directory_path() / "wpa3_crack_invalid.txt";
	{
		ofstream f(tmp);
		f << "WPA*02*tooshort\n" << "WPA*99*foo*bar\n" << "not a wpa line\n";
	}
	const auto r = hostapd::crack_pmk_hashes(tmp, "anypassword");
	CHECK_EQ(r.total, 0);
	CHECK_EQ(r.cracked, 0);
	remove(tmp);
}

// -----------------

TEST_CASE("crack_pmk_hashes - SHA256: correct PSK cracks the hash") {
	const path tmp = temp_directory_path() / "wpa3_crack_sha256_good.txt";
	{
		ofstream f(tmp);
		f << SHA256_HASH << "\n";
	}
	const auto r = hostapd::crack_pmk_hashes(tmp, "password123");
	CHECK_EQ(r.total, 1);
	CHECK_EQ(r.cracked, 1);
	remove(tmp);
}

TEST_CASE("crack_pmk_hashes - SHA256: wrong PSK cracks nothing") {
	const path tmp = temp_directory_path() / "wpa3_crack_sha256_wrong.txt";
	{
		ofstream f(tmp);
		f << SHA256_HASH << "\n";
	}
	const auto r = hostapd::crack_pmk_hashes(tmp, "wrongpassword");
	CHECK_EQ(r.total, 1);
	CHECK_EQ(r.cracked, 0);
	remove(tmp);
}

TEST_CASE("crack_pmk_hashes - SHA1: correct PSK cracks the hash" *
	doctest::skip(hw_capabilities::run_cmd({ "which", "hcxpmktool" }, nullopt, false) != 0)) {
	const path tmp = temp_directory_path() / "wpa3_crack_sha1_good.txt";
	{
		ofstream f(tmp);
		f << SHA1_HASH << "\n";
	}
	const auto r = hostapd::crack_pmk_hashes(tmp, "password123");
	CHECK_EQ(r.total, 1);
	CHECK_EQ(r.cracked, 1);
	remove(tmp);
}

TEST_CASE("crack_pmk_hashes - SHA1: wrong PSK cracks nothing" *
	doctest::skip(hw_capabilities::run_cmd({ "which", "hcxpmktool" }, nullopt, false) != 0)) {
	const path tmp = temp_directory_path() / "wpa3_crack_sha1_wrong.txt";
	{
		ofstream f(tmp);
		f << SHA1_HASH << "\n";
	}
	const auto r = hostapd::crack_pmk_hashes(tmp, "wrongpassword");
	CHECK_EQ(r.total, 1);
	CHECK_EQ(r.cracked, 0);
	remove(tmp);
}

TEST_CASE("crack_pmk_hashes - mixed SHA1+SHA256: both counted in total") {
	const path tmp = temp_directory_path() / "wpa3_crack_mixed.txt";
	{
		ofstream f(tmp);
		f << SHA1_HASH << "\n" << SHA256_HASH << "\n";
	}
	const auto r = hostapd::crack_pmk_hashes(tmp, "anypassword");
	CHECK_EQ(r.total, 2);
	remove(tmp);
}
