#include "config/RunStatus.h"
#include "config/Actor_Config/Actor_Config_internal.h"
#include "config/global_config.h"
#include "system/hw_capabilities.h"
#include "system/hw_info.h"
#include "system/utils.h"

namespace wpa3_tester{
using namespace std;
using nlohmann::json;
using namespace Tins;
using namespace filesystem;

vector<ActorPtr> RunStatus::internal_options(){
	const bool use_cache = get_global_config().value("use_hw_cache", true);
	optional<path> hw_cache;
	if(use_cache){
		const path hw_cache_dir = root_dir().parent_path() / "data" / "cache" / "scan";
		create_public_dirs(hw_cache_dir);
		hw_cache = hw_cache_dir / "internal_iface.json";
	}
	vector<ActorPtr> options;
	for(const auto &[iface_name, radio_name, iface_type]:
		hw_capabilities::list_interfaces(InterfaceType::Wifi, nullopt)){
		auto cfg = ActorPtr(make_shared<Actor_Config_internal>());
		cfg->set(SK::iface, iface_name);
		cfg->set(SK::radio, radio_name);
		//FIXME error if not change
		cfg->set(SK::mac, hw_capabilities::get_mac_address(iface_name, nullopt));
		cfg->load_hw_info(hw_cache);
		options.emplace_back(cfg);
	}
	return options;
}
}
