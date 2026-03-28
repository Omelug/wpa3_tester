#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include "system/hw_capabilities.h"
#include <stdexcept>

using namespace std;
using namespace wpa3_tester;
namespace wpa3_tester {
    TEST_CASE("hw_capabilities::freq_to_channel") {
        SUBCASE("2.4 GHz band") {
            CHECK((hw_capabilities::freq_to_channel(2412) == 1));
            CHECK((hw_capabilities::freq_to_channel(2437) == 6));
            CHECK((hw_capabilities::freq_to_channel(2472) == 13));
            CHECK((hw_capabilities::freq_to_channel(2484) == 14));
        }

        SUBCASE("5 GHz band") {
            CHECK((hw_capabilities::freq_to_channel(5180) == 36));
            CHECK((hw_capabilities::freq_to_channel(5500) == 100));
            CHECK((hw_capabilities::freq_to_channel(5885) == 177));
        }

        SUBCASE("6 GHz band") {
            CHECK((hw_capabilities::freq_to_channel(5955) == 1));
            CHECK((hw_capabilities::freq_to_channel(6455) == 101));
            CHECK((hw_capabilities::freq_to_channel(7115) == 233));
        }

        SUBCASE("Invalid frequencies") {
            CHECK_THROWS_AS(hw_capabilities::freq_to_channel(2411), invalid_argument);
            CHECK_THROWS_AS(hw_capabilities::freq_to_channel(3000), invalid_argument);
            CHECK_THROWS_AS(hw_capabilities::freq_to_channel(-1), invalid_argument);
        }
    }

    TEST_CASE("hw_capabilities::channel_to_freq") {
        SUBCASE("2.4 GHz band") {
            CHECK((hw_capabilities::channel_to_freq(1) == 2412));
            CHECK((hw_capabilities::channel_to_freq(6) == 2437));
            CHECK((hw_capabilities::channel_to_freq(13) == 2472));
            CHECK((hw_capabilities::channel_to_freq(14) == 2484));
        }

        SUBCASE("5 GHz band") {
            CHECK((hw_capabilities::channel_to_freq(36) == 5180));
            CHECK((hw_capabilities::channel_to_freq(100) == 5500));
            CHECK((hw_capabilities::channel_to_freq(177) == 5885));
        }

        SUBCASE("6 GHz band") {
            CHECK((hw_capabilities::channel_to_freq(1, WifiBand::BAND_6) == 5955));
            CHECK((hw_capabilities::channel_to_freq(101, WifiBand::BAND_6) == 6455));
            CHECK((hw_capabilities::channel_to_freq(233, WifiBand::BAND_6) == 7115));
        }

        SUBCASE("Invalid channels") {
            CHECK_THROWS_AS(hw_capabilities::channel_to_freq(0), invalid_argument);
            CHECK_THROWS_AS(hw_capabilities::channel_to_freq(15), invalid_argument);
            CHECK_THROWS_AS(hw_capabilities::channel_to_freq(-1), invalid_argument);
        }
    }

    TEST_CASE("freq_to_channel and channel_to_freq roundtrip") {
        SUBCASE("Roundtrip consistency") {
            vector<tuple<int, int, WifiBand>> test_cases = {
                {2412, 1, WifiBand::BAND_2_4}, {2437, 6, WifiBand::BAND_2_4_or_5}, {2472, 13, WifiBand::BAND_2_4},  // 2.4 GHz
                {5180, 36, WifiBand::BAND_5}, {5500, 100, WifiBand::BAND_2_4_or_5}, {5885, 177, WifiBand::BAND_5},  // 5 GHz
                {5955, 1, WifiBand::BAND_6}, {6455, 101, WifiBand::BAND_6}, {7115, 233, WifiBand::BAND_6}   // 6 GHz
            };

            for (auto [freq, channel, band] : test_cases){
                CHECK((hw_capabilities::channel_to_freq(channel, band) == freq));
                CHECK((hw_capabilities::freq_to_channel(freq) == channel));
            }
        }
    }
}
