#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <fstream>
#include <filesystem>
#include "config/RunStatus.h"
#include "default.h"
#include "root_dir_helper.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace wpa3_tester;
namespace fs = filesystem;

namespace{
const string test_name = "integration_no_module_test";

bool hwsim_available(){
	if(hw_capabilities::run_cmd({"modprobe", "mac80211_hwsim", "radios=1"}, nullopt, false) != 0) return false;
	hw_capabilities::run_cmd({"udevadm", "settle"}, nullopt, false);
	const bool ok = !hw_capabilities::list_interfaces(InterfaceType::WifiVirtualHwsim, nullopt).empty();
	hw_capabilities::run_cmd({"modprobe", "-r", "mac80211_hwsim"}, nullopt, false);
	return ok;
}

// IsolatedRootDir already creates <root_dir()>/attack_config/ for its own global_config.yaml;
// reusing that same directory means the config file, run folder and global config all land
// under one isolated tree, cleaned up in one shot when isolated goes out of scope.
fs::path write_config(const fs::path &root){
	const fs::path config_path = root / "attack_config" / "no_module_test.yaml";
	ofstream f(config_path);
	f << "$schema: https://json-schema.org/draft/2020-12/schema\n"
		 "name: " << test_name << "\n"
		 "attacker_module: this_module_does_not_exist_xyz\n"
		 "actors:\n"
		 "  sta:\n"
		 "    source: simulation\n"
		 "delete_old: true\n"
		 "rewrite: all\n"
		 "save_log: true\n";
	return config_path;
}
}

TEST_CASE("RunStatus::execute - attacker_module not present in any map still completes"){
	if(!hwsim_available()){
		MESSAGE("Skipping: mac80211_hwsim not available on this kernel");
		return;
	}

	const test_helpers::IsolatedRootDir isolated("no_module_test");
	const fs::path config_path = write_config(isolated.dir);
	// mirrors RunStatus::BASE_FOLDER() (data/wpa3_test next to root_dir()); private, so can't call it directly
	const fs::path run_folder = root_dir().parent_path() / "data" / DATA_TEST / test_name;

	RunStatus rs(config_path);

	CHECK_NOTHROW(rs.execute());

	CHECK(fs::exists(run_folder / DONE_FILE));
	CHECK_FALSE(fs::exists(run_folder / ERROR_FILE));

	hw_capabilities::run_cmd({"modprobe", "-r", "mac80211_hwsim"}, nullopt, false);
}
