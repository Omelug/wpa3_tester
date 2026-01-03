#include "config/RunStatus.h"
#include "logger/log.h"
#include "attacks/attacks.h"
#include <filesystem>
#include <iostream>
#include "../../include/system/nl80211_compat.h"

using namespace std;


void RunStatus::setup_test(){
    namespace fs = filesystem;
    const fs::path base = fs::current_path();
    const fs::path data_root = base / "data" / "wpa3_test" / "run" / config["name"];
    const fs::path last_run = data_root / "last_run";

    // Ensure parent directories exist
    error_code ec;
    fs::create_directories(data_root, ec);
    if (ec) {
        cerr << "CRITICAL ERROR: " << last_run.string() << " Error: " << ec.message() << endl;
        log(LogLevel::ERROR, "Failed to create run base directory: %s: %s", data_root.string().c_str(), ec.message().c_str());
        throw runtime_error("Unable to create run base directory");
    }

    // Recreate last_run directory empty
    if (fs::exists(last_run, ec)) {
        fs::remove_all(last_run, ec);
        if (ec) {
            log(LogLevel::ERROR, "Failed to clean last_run directory: %s: %s", last_run.string().c_str(), ec.message().c_str());
            throw runtime_error("Unable to clean last_run directory");
        }
    }
    fs::create_directories(last_run, ec);
    if (ec) {
        log(LogLevel::ERROR, "Failed to create last_run directory: %s: %s",last_run.string().c_str(), ec.message().c_str());
        throw runtime_error("Unable to create last_run directory");
    }

    run_folder = last_run.string();
    save_actor_interface_mapping();

    process_manager.init_logging(run_folder);

	attack_setup[config["attacker_module"]](*this);
}
