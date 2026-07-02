#include "config/Actor_Config/ActorPtr.h"
#include "logger/error_log.h"
#include <chrono>
#include <fstream>
#include <nlohmann/json.hpp>

#include "system/utils.h"

namespace wpa3_tester::report{
using namespace std;
using namespace filesystem;
using json = nlohmann::json;

// devices/<perm_mac>/last.json symlink to last
const path device_path = path(PROJECT_ROOT_DIR).parent_path() / "data" / "devices";

//TODO ? zjednosušit poocí HWInfo, nebo se to bude plést, pokud sem přidám víc info?

bool add_device(ActorPtr actor){
	const auto &perm_mac_opt = (*actor)[SK::permanent_mac];
	if(!perm_mac_opt.has_value())
		throw config_err("add_device: actor has no permanent_mac");
//if not clonflict, merge?
	path dev_dir = device_path / *perm_mac_opt;
	create_public_dirs(dev_dir);

	const json caps = actor->hw_info_caps_to_flat_json();
	const string caps_dump = caps.dump();
	const path symlink_path = dev_dir / "last.json";

	for(const auto &entry: directory_iterator(dev_dir)){
		if(entry.is_symlink()) continue;  // is_symlink() uses symlink_status — does not follow
		if(!entry.is_regular_file()) continue;
		if(entry.path().extension() != ".json") continue;
		try{
			ifstream f(entry.path());
			const json stored = json::parse(f);
			const auto caps_key = stored.contains("caps") ? stored.at("caps").dump() : stored.dump();
			if(caps_key == caps_dump){
				set_public_perms(entry.path());
				if(is_symlink(symlink_path) || exists(symlink_path)) remove(symlink_path);
				create_symlink(entry.path().filename(), symlink_path);
				set_public_perms(symlink_path);
				return false;
			}
		} catch(const exception &){}
	}

	const auto ts = chrono::duration_cast<chrono::milliseconds>(chrono::system_clock::now().time_since_epoch()).count();
	const path new_file = dev_dir / (to_string(ts) + ".json");
	{
		json record = json::object();
		record["source"] = actor.get(SK::source);
		record["caps"] = caps;
		ofstream f(new_file);
		f << record.dump(2) << '\n';
	}

	if(is_symlink(symlink_path) || exists(symlink_path)) remove(symlink_path);
	create_symlink(new_file.filename(), symlink_path);
	set_public_perms(new_file);
	set_public_perms(symlink_path);
	return true;
}
}
