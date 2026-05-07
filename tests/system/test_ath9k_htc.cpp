#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <regex>
#include <string>
#include "system/firmware/ath9k_htc.h"

using namespace std;
using namespace wpa3_tester;

namespace wpa3_tester {

TEST_CASE("firmware::get_random_ath_masker_mac - preserves first 5 octets") {
    const string attacker_mac = "aa:bb:cc:dd:ee:ff";
    const string result = firmware::get_random_ath_masker_mac(attacker_mac);

    // Split both
    auto split = [](const string &s) {
        vector<string> parts;
        stringstream ss(s);
        string seg;
        while (getline(ss, seg, ':')) parts.push_back(seg);
        return parts;
    };

    auto in_parts  = split(attacker_mac);
    auto out_parts = split(result);

    REQUIRE_EQ(out_parts.size(), 6);
    for (int i = 0; i < 5; ++i)
        CHECK_EQ(out_parts[i], in_parts[i]);
}

TEST_CASE("firmware::get_random_ath_masker_mac - last octet is valid hex in [01,ff]") {
    const string result = firmware::get_random_ath_masker_mac("11:22:33:44:55:66");

    vector<string> parts;
    stringstream ss(result);
    string seg;
    while (getline(ss, seg, ':')) parts.push_back(seg);

    REQUIRE_EQ(parts.size(), 6);

    const string &last = parts[5];
    CHECK_EQ(last.size(), 2);

    int val = stoi(last, nullptr, 16);
    CHECK_GE(val, 0);
    CHECK_LE(val, 255);
}

TEST_CASE("firmware::get_random_ath_masker_mac - result is valid MAC format") {
    const string result = firmware::get_random_ath_masker_mac("de:ad:be:ef:00:01");
    const regex mac_re("^([0-9a-f]{2}:){5}[0-9a-f]{2}$");
    CHECK(regex_match(result, mac_re));
}

}
