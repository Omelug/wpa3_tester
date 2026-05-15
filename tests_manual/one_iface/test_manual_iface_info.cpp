#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <nlohmann/json.hpp>

#include "../manual_test_core/manual_test_wizards.h"
#include "attacks/scan/iface_info.h"
#include "config/Actor_config.h"
#include "config/ActorPtr.h"
#include "config/RunStatus.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester;
using namespace wpa3_tester::manual_tests;

TEST_CASE("iface_info_report"){
    auto iface_ptr = get_iface_wizard();
    REQUIRE_NE(iface_ptr, nullptr);
    const string &iface = *iface_ptr;

    const int ch_num = get_2_4_channel_wizard();

    const string perm_mac = hw_capabilities::get_permanent_mac(iface, nullopt);
    cout << "Interface    : " << iface << "\n";
    cout << "Permanent MAC: " << (perm_mac.empty() ? "unknown" : perm_mac) << "\n";

    // ----- build RunStatus -----
    RunStatus rs;

    ActorPtr scanner(make_shared<Actor_config>());
    scanner[SK::iface]       = iface;
    scanner[SK::sniff_iface] = iface;
    if(!perm_mac.empty()) scanner[SK::mac] = perm_mac;
    rs.actors["scanner"] = scanner;

    // minimal config so tshark's add_nets_header and attack_config are accessible
    rs.config()["actors"]["scanner"] = nlohmann::json::object();
    rs.config()["attack_config"]["channel"] = ch_num;

    const path out_dir = path(PROJECT_ROOT_DIR).parent_path() / "data" / "tests" / ("iface_info_" + iface);
    rs.run_folder(out_dir);

    iface_info::run_attack(rs);
}
