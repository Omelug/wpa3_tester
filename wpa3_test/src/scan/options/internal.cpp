#include <fstream>
#include "config/RunStatus.h"
#include "config/Actor_Config/Actor_Config_internal.h"
#include "system/hw_capabilities.h"
#include "system/hw_info.h"
#include "system/utils.h"

namespace wpa3_tester{
using namespace std;
using nlohmann::json;
using namespace Tins;
using namespace filesystem;

vector<ActorPtr> RunStatus::internal_options(){
	const path hw_cache_dir = path(PROJECT_ROOT_DIR).parent_path() / "data" / "cache" /"scan";
	create_public_dirs(hw_cache_dir);
	auto hw_cache = hw_cache_dir / "internal_iface.json";
	vector<ActorPtr> options;
	for(const auto &[iface_name, radio_name, iface_type]:
		hw_capabilities::list_interfaces(InterfaceType::Wifi, nullopt)){
		auto cfg = ActorPtr(make_shared<Actor_Config_internal>());
		cfg->set(SK::iface, iface_name);
		cfg->set(SK::radio, radio_name);
		//FIXME error if not change
		cfg->set(SK::mac, hw_capabilities::get_mac_address(iface_name, nullopt).to_string());
		cfg->load_hw_info(hw_cache);
		options.emplace_back(cfg);
		}
	return options;
}

}
