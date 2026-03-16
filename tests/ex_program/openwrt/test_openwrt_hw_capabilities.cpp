#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <string>
#include <fstream>
#include <sstream>
#include <boost/assert/source_location.hpp>

#include "ex_program/external_actors/openwrt/OpenWrtConn.h"
#include "config/Actor_config.h"
#include "logger/error_log.h"

using namespace std;
using namespace wpa3_tester;
using namespace filesystem;
path this_file = source_location::current().file_name();

class MockOpenWrtConn : public OpenWrtConn {
public:
    mutable int mock_ret = 0;
    mutable std::string mock_output = "";
    std::string exec(const std::string &cmd, int * ret_err = nullptr) const override {
        if (ret_err) *ret_err = mock_ret;
        return mock_output;
    }
};

TEST_CASE("parse_hw_capabilities - OpenWrt phy0 info") {
    Actor_config cfg;

    ifstream file("iw_phy_output.txt");
    REQUIRE(file.is_open());
    stringstream buffer;
    buffer << file.rdbuf();
    const string output = buffer.str();
    file.close();

    OpenWrtConn::parse_hw_capabilities(cfg, output);

    CHECK((cfg.bool_conditions["2_4GHz"] == true));
    CHECK((cfg.bool_conditions["5GHz"] == false));
    CHECK((cfg.bool_conditions["6GHz"] == false));

    CHECK((cfg.bool_conditions["AP"] == true));
    CHECK((cfg.bool_conditions["STA"] == true));
    CHECK((cfg.bool_conditions["monitor"] == true));

    CHECK((cfg.bool_conditions["80211n"] == true));
    CHECK((cfg.bool_conditions["80211ac"] == false));
    CHECK((cfg.bool_conditions["80211ax"] == false));
}

TEST_CASE("parse_hw_capabilities - empty output") {
    Actor_config cfg;
    const string output = "";

    OpenWrtConn::parse_hw_capabilities(cfg, output);

    CHECK((cfg.bool_conditions["2_4GHz"] == false));
    CHECK((cfg.bool_conditions["AP"] == false));
    CHECK((cfg.bool_conditions["80211n"] == false));
}

TEST_CASE("get_hw_capabilities - exec failure") {
    Actor_config cfg;
    MockOpenWrtConn conn;
    conn.mock_ret = 1;
    conn.mock_output = "iw: command not found";

    CHECK_THROWS_AS(conn.get_hw_capabilities(cfg, "radio0"), ex_conn_err);
}

TEST_CASE("get_radio_list - mock wifi status") {
    MockOpenWrtConn conn;

    // Mock output for wifi status
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
    CHECK((radios.size() == 2));
    CHECK((radios[0] == "radio0"));
    CHECK((radios[1] == "radio1"));
}
