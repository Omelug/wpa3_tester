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
#include "system/hw_info.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester;
using namespace wpa3_tester::manual_tests;

TEST_CASE("iface_info_report"){
    auto iface_ptr = get_iface_wizard();
    REQUIRE_NE(iface_ptr, nullptr);
    const string &iface = *iface_ptr;

    const int ch_num = get_2_4_channel_wizard();

    // ----- collect and cache hw_info -----
    const path hw_cache = path(PROJECT_ROOT_DIR).parent_path() / "data" / "cache" /"scan" / "internal_iface.json";
    ActorPtr scanner_cfg(make_shared<Actor_config>());
    scanner_cfg->set(SK::iface, iface);
    const HwInfo hw = scanner_cfg->get_hw_info(hw_cache);

    cout << "Interface    : " << iface << "\n";
    cout << "Permanent MAC: " << (hw.permanent_mac.empty() ? "unknown" : hw.permanent_mac) << "\n";
    cout << "Driver       : " << (hw.driver.empty() ? "unknown" : hw.driver) << "\n";
    cout << "hw_info saved to: " << hw_cache << "\n";

    // ----- build RunStatus -----
    RunStatus rs;

    ActorPtr scanner(make_shared<Actor_config>());
    scanner->set(SK::iface, iface);
    scanner->set(SK::sniff_iface, iface);
    if(!hw.permanent_mac.empty()) scanner->set(SK::mac, hw.permanent_mac);
    rs.actors["scanner"] = scanner;

    // minimal config so tshark's add_nets_header and attack_config are accessible
    rs.config()["actors"]["scanner"] = nlohmann::json::object();
    rs.config()["attack_config"]["channel"] = ch_num;

    const path out_dir = path(PROJECT_ROOT_DIR).parent_path() / "data" / "tests" / ("iface_info_" + iface);
    rs.run_folder(out_dir);

    iface_info::run_attack(rs);
}
