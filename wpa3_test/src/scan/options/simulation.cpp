#include "config/RunStatus.h"
#include "config/Actor_Config/Actor_Config_sim.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "system/hw_info.h"

namespace wpa3_tester{
using namespace std;
using nlohmann::json;
using namespace Tins;
using namespace filesystem;

vector<ActorPtr> RunStatus::create_simulation(const size_t n_radios){
	log(LogLevel::INFO, "Loading mac80211_hwsim with {} radios", n_radios);
	hw_capabilities::run_cmd({"modprobe", "mac80211_hwsim", "radios=" + to_string(n_radios)});
	hw_capabilities::run_cmd({"udevadm", "settle"}, nullopt, false);

	// rename all new Wi-Fi interfaces to hwsim_<orig> so they get WifiVirtualHwsim type
	for(const auto &[name, radio, type]: hw_capabilities::list_interfaces(InterfaceType::Wifi, nullopt)){
		hw_capabilities::run_cmd({"ip", "link", "set", name, "name", HWSIM_IFACE_PREFIX + name});
	}
	hw_capabilities::run_cmd({"udevadm", "settle"}, nullopt, false);

	//only hwsim_ prefixed interfaces are returned
	vector<ActorPtr> options;
	for(const auto &[name, radio, type]: hw_capabilities::list_interfaces(InterfaceType::WifiVirtualHwsim, nullopt)){
		auto cfg = ActorPtr(make_shared<Actor_Config_sim>());
		cfg->set(SK::iface, name);
		cfg->set(SK::radio, radio);
		hw_capabilities::get_nl80211_caps(cfg);
		options.emplace_back(cfg);
	}
	log(LogLevel::INFO, "Created {} simulation interface(s)", options.size());
	return options;
}
}
