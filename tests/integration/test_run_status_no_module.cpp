#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <fstream>
#include <filesystem>
#include "config/RunStatus.h"
#include "default.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace wpa3_tester;
namespace fs = filesystem;

namespace{
// RunStatus needs the config file to live under a directory literally named
// "attack_config" (see relative_from() in system/utils.cpp).
const fs::path temp_root = fs::temp_directory_path() / "wpa3_tester_no_module_test";
const fs::path config_dir = temp_root / "attack_config";
const fs::path config_path = config_dir / "no_module_test.yaml";
const string test_name = "integration_no_module_test";

// mirrors RunStatus::BASE_FOLDER (data/wpa3_test next to wpa3_test/)
const fs::path run_folder = fs::path(PROJECT_ROOT_DIR).parent_path() / "data" / "wpa3_test" / test_name;

bool hwsim_available(){
    if(hw_capabilities::run_cmd({"modprobe", "mac80211_hwsim", "radios=1"}, nullopt, false) != 0) return false;
    hw_capabilities::run_cmd({"udevadm", "settle"}, nullopt, false);
    const bool ok = !hw_capabilities::list_interfaces(InterfaceType::WifiVirtualHwsim, nullopt).empty();
    hw_capabilities::run_cmd({"modprobe", "-r", "mac80211_hwsim"}, nullopt, false);
    return ok;
}

void write_config(){
    fs::create_directories(config_dir);
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
}

void cleanup(){
    error_code ec;
    fs::remove_all(run_folder, ec);
    fs::remove_all(temp_root, ec);
    hw_capabilities::run_cmd({"modprobe", "-r", "mac80211_hwsim"}, nullopt, false);
}
}

TEST_CASE("RunStatus::execute - attacker_module not present in any map still completes"){
    if(!hwsim_available()){
        MESSAGE("Skipping: mac80211_hwsim not available on this kernel");
        return;
    }

    write_config();
    RunStatus rs(config_path);

    CHECK_NOTHROW(rs.execute());

    CHECK(fs::exists(run_folder / DONE_FILE));
    CHECK_FALSE(fs::exists(run_folder / ERROR_FILE));

    cleanup();
}
