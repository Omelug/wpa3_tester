#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include "config/RunStatus.h"
#include "root_dir_helper.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace wpa3_tester;

TEST_CASE("RunStatus::create_simulation - loads hwsim and returns simulation actor options"){
    // isolates root_dir() (and the global_config cache) so the ignore_interfaces lookup inside
    // list_interfaces() never depends on real project config.
    const test_helpers::IsolatedRootDir isolated("create_simulation_test");

    const auto options = RunStatus::create_simulation(1);

    if(options.empty()){
        MESSAGE("Skipping: mac80211_hwsim not available on this kernel");
        return;
    }

    REQUIRE_GE(options.size(), 1);
    for(const auto &opt: options){
        CHECK_EQ(opt.get(SK::source), "simulation");
        CHECK(opt.get(SK::iface).starts_with(HWSIM_IFACE_PREFIX));
        CHECK_FALSE(opt.get(SK::radio).empty());
    }

    hw_capabilities::run_cmd({"modprobe", "-r", "mac80211_hwsim"}, nullopt, false);
}

TEST_CASE("RunStatus::create_simulation - creates one interface per requested radio"){
    const test_helpers::IsolatedRootDir isolated("create_simulation_multi_test");

    const auto options = RunStatus::create_simulation(2);

    if(options.empty()){
        MESSAGE("Skipping: mac80211_hwsim not available on this kernel");
        return;
    }

    CHECK_EQ(options.size(), 2);

    hw_capabilities::run_cmd({"modprobe", "-r", "mac80211_hwsim"}, nullopt, false);
}
