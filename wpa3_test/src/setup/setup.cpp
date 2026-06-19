#include <filesystem>
#include "attacks/attacks.h"
#include "config/RunStatus.h"
#include "logger/log.h"

#include "logger/error_log.h"
#include "system/utils.h"

namespace wpa3_tester{
using namespace std;
using namespace filesystem;

void RunStatus::setup_test(){
	// Recreate last_run directory empty
	error_code ec;
	if(exists(_run_folder, ec)){
		remove_all(_run_folder, ec);
		if(ec) throw run_err("Failed to clean last_run directory: {}:{} ", _run_folder, ec.message());
	}

	create_public_dirs(_run_folder, ec);
	if(ec) throw run_err("Failed to create last_run directory: {}:{}", _run_folder, ec.message());

	save_actor_interface_mapping();
	process_manager.init_logging(_run_folder);

	const auto module_name = _config.at("attacker_module");

	if(const auto run_it = attack_module_maps::setup_map.find(module_name); run_it != attack_module_maps::setup_map.
		end()){
		run_it->second(*this);
	} else{
		log(LogLevel::DEBUG, "setup function not set");
	}
}
}
