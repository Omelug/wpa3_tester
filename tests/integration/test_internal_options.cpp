#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <algorithm>
#include <set>
#include "config/RunStatus.h"
#include "root_dir_helper.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace wpa3_tester;

namespace{
set<string> wifi_iface_names(){
    set<string> names;
    for(const auto &info: hw_capabilities::list_interfaces(InterfaceType::Wifi, nullopt)) names.insert(info.name);
    return names;
}
}

TEST_CASE("RunStatus::internal_options - discovers a real hwsim Wifi interface"){

	const test_helpers::IsolatedRootDir isolated("internal_options_test");
    const auto before = wifi_iface_names();

    if(hw_capabilities::run_cmd({"modprobe", "mac80211_hwsim", "radios=1"}, nullopt, false) != 0){
        MESSAGE("Skipping: mac80211_hwsim not available on this kernel");
        return;
    }
    hw_capabilities::run_cmd({"udevadm", "settle"}, nullopt, false);

    // deliberately not renamed to hwsim_* here: internal_options() scans plain InterfaceType::Wifi,
    // which is exactly what a freshly loaded, unrenamed hwsim radio shows up as.
    const auto after = wifi_iface_names();
    string new_iface;
    for(const auto &name: after) if(!before.contains(name)) new_iface = name;

    if(new_iface.empty()){
        MESSAGE("Skipping: no new Wifi interface appeared after loading mac80211_hwsim");
        hw_capabilities::run_cmd({"modprobe", "-r", "mac80211_hwsim"}, nullopt, false);
        return;
    }

    const auto options = RunStatus::internal_options();

    const auto it = ranges::find_if(options,[&](const ActorPtr &opt){
	    return opt.get(SK::iface) == new_iface;
    });
    REQUIRE_NE(it, options.end());

    const ActorPtr &opt = *it;
    CHECK_EQ(opt.get(SK::source), "internal");
    CHECK_EQ(opt.get(SK::mac), hw_capabilities::get_mac_address(new_iface, nullopt).to_string());
    CHECK_EQ(opt.get(SK::driver_name), "mac80211_hwsim");
    CHECK_FALSE(opt.get(SK::permanent_mac).empty());

    hw_capabilities::run_cmd({"modprobe", "-r", "mac80211_hwsim"}, nullopt, false);
}
