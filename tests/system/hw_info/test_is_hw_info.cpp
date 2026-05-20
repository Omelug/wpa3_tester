#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "system/hw_info.h"

using namespace wpa3_tester;

TEST_CASE("HwInfo::is_hw_info(BK) - hardware capability keys") {
    CHECK(HwInfo::is_hw_info(BK::AP));
    CHECK(HwInfo::is_hw_info(BK::STA));
    CHECK(HwInfo::is_hw_info(BK::monitor));
    CHECK(HwInfo::is_hw_info(BK::GHz2_4));
    CHECK(HwInfo::is_hw_info(BK::GHz5));
    CHECK(HwInfo::is_hw_info(BK::GHz6));
    CHECK(HwInfo::is_hw_info(BK::w80211n));
    CHECK(HwInfo::is_hw_info(BK::w80211ac));
    CHECK(HwInfo::is_hw_info(BK::w80211ax));
    CHECK(HwInfo::is_hw_info(BK::beacon_prot));
}

TEST_CASE("HwInfo::is_hw_info(BK) - non-hardware keys return false") {
    CHECK_FALSE(HwInfo::is_hw_info(BK::injection));
}

TEST_CASE("HwInfo::is_hw_info(SK) - hardware string keys") {
    CHECK(HwInfo::is_hw_info(SK::permanent_mac));
    CHECK(HwInfo::is_hw_info(SK::driver_name));
    CHECK(HwInfo::is_hw_info(SK::driver_hash));
    CHECK(HwInfo::is_hw_info(SK::module_hash));
}

TEST_CASE("HwInfo::is_hw_info(SK) - non-hardware string keys return false") {
    CHECK_FALSE(HwInfo::is_hw_info(SK::iface));
    CHECK_FALSE(HwInfo::is_hw_info(SK::netns));
    CHECK_FALSE(HwInfo::is_hw_info(SK::channel));
}
