#include "system/hw_info.h"

#include <fstream>
#include "attacks/mc_mitm/MonitorSocket.h"
#include "config/Actor_Config/ActorPtr.h"
#include "config/Actor_Config/Actor_config.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"

namespace wpa3_tester{
using namespace std;
using namespace filesystem;

// -----------------  HwInfo

nlohmann::json HwInfo::to_json() const{
	nlohmann::json j;
	j.update(actor->hw_info_caps_to_flat_json());
	return j;
}

void HwInfo::from_json(const nlohmann::json &j) const{
	for(const auto sk: sk_values()){
		if(!is_hw_info(sk)) continue;
		const auto name = string(sk_name(sk));
		if(j.contains(name) && j.at(name).is_string() && !j.at(name).get<string>().empty()) actor->set(
			sk, j.at(name).get<string>());
	}
	actor->caps_from_flat_json(j);
}

// -----------------  Actor_config::get_hw_info
void Actor_config::load_hw_info(const optional<path> &cache){
	const string iface = get(SK::iface);
	const string perm_mac = hw_capabilities::get_permanent_mac(iface, (*this)[SK::netns]);

	// ----- try cache -----
	if(cache.has_value() && exists(*cache)){
		try{
			ifstream f(*cache);
			const auto json_cache = nlohmann::json::parse(f);
			if(json_cache.contains(perm_mac)){ //perm_mac is cache key
				HwInfo hw_cached;
				hw_cached.actor = shared_from_this();
				hw_cached.from_json(json_cache.at(perm_mac));
				log(LogLevel::DEBUG, "HW Info from cache");
				return;
			}
		} catch(const exception &e){
			log(LogLevel::WARNING, "get_hw_info: cache read failed ({}): {}", cache->string(), e.what());
		}
	}

	// ----- collect info -----
	set(SK::permanent_mac, perm_mac);
	const auto netns = (*this)[SK::netns];
	set(SK::driver_name, hw_capabilities::get_driver_name(iface, netns));
	set(SK::driver_hash, hw_capabilities::get_driver_hash(get(SK::driver_name)));
	set(SK::module_hash, hw_capabilities::get_module_hash(get(SK::driver_name)));

	ActorPtr self(shared_from_this());
	hw_capabilities::get_nl80211_caps(self);

	// ----- write cache -----
	if(cache.has_value()){
		try{
			create_directories(cache->parent_path());
			permissions(cache->parent_path(), perms::all);
			nlohmann::json json_cache = nlohmann::json::object();
			if(exists(*cache)){
				ifstream f(*cache);
				auto parsed = nlohmann::json::parse(f, nullptr, false);
				if(!parsed.is_discarded()) json_cache = parsed;
			}
			HwInfo hw_snapshot;
			hw_snapshot.actor = shared_from_this();
			json_cache[perm_mac] = hw_snapshot.to_json();
			{
				ofstream f(*cache);
				f << json_cache.dump(2) << '\n';
			}
			set_public_perms(cache.value());
		} catch(const exception &e){
			log(LogLevel::WARNING, "get_hw_info: cache write failed: {}", e.what());
		}
	}
}
}
