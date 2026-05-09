#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <fstream>
#include <source_location>
#include <sstream>
#include <string>
#include "config/Actor_config.h"
#include "ex_program/external_actors/openwrt/OpenWrtConn.h"
#include "logger/error_log.h"

using namespace std;
using namespace wpa3_tester;
using namespace filesystem;
path this_file = source_location::current().file_name();

class MockOpenWrtConn: public OpenWrtConn{
public:
    mutable int mock_ret = 0;
    mutable string mock_output;

    string exec(const string &, bool, int *ret_err) const override{
        if(ret_err) *ret_err = mock_ret;
        return mock_output;
    }
};

TEST_CASE("parse_hw_capabilities - OpenWrt phy0 info"){
    Actor_config cfg;

    ifstream file("iw_phy_output.txt");
    REQUIRE(file.is_open());
    stringstream buffer;
    buffer << file.rdbuf();
    const string output = buffer.str();
    file.close();

    OpenWrtConn::parse_hw_capabilities(cfg, output);

    CHECK(cfg[BK::GHz2_4]);
    CHECK_EQ(cfg[BK::GHz5], false);
    CHECK_EQ(cfg[BK::GHz6], false);

    CHECK(cfg[BK::AP]);
    CHECK(cfg[BK::STA]);
    CHECK(cfg[BK::monitor]);

    CHECK(cfg[BK::w80211n]);
    CHECK_EQ(cfg[BK::w80211ac], false);
    CHECK_EQ(cfg[BK::w80211ax], false);
}

TEST_CASE("parse_hw_capabilities - empty output"){
    Actor_config cfg;
    const string output;
    OpenWrtConn::parse_hw_capabilities(cfg, output);

    CHECK_EQ(cfg[BK::GHz2_4], false);
    CHECK_EQ(cfg[BK::AP], false);
    CHECK_EQ(cfg[BK::w80211n], false);
}

TEST_CASE("get_hw_capabilities - exec failure"){
    Actor_config cfg;
    MockOpenWrtConn conn;
    conn.mock_ret = 1;
    conn.mock_output = "iw: command not found";

    CHECK_THROWS_AS(conn.get_hw_capabilities(cfg, "radio0"), ex_conn_err);
}

TEST_CASE("get_radio_list - mock wifi status"){
    MockOpenWrtConn conn;

    // Mock output for Wi-Fi status
    conn.mock_output = R"(
{
    "radio0": {
        "up": true,
        "pending": false,
        "autostart": true,
        "disabled": false,
        "interfaces": []
    },
    "radio1": {
        "up": false,
        "pending": false,
        "autostart": true,
        "disabled": true,
        "interfaces": []
    }
}
)";

    const auto radios = conn.get_radio_list();
    CHECK_EQ(radios.size(), 2);
    CHECK_EQ(radios[0], "radio0");
    CHECK_EQ(radios[1], "radio1");
}