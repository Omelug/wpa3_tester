#include "config/RunStatus.h"
#include "logger/log.h"
#include "attacks/attacks.h"
#include <filesystem>

namespace wpa3_tester{
    using namespace std;
    using namespace filesystem;

    void RunStatus::setup_test(){

        // Recreate last_run directory empty
        error_code ec;
        if (exists(run_folder, ec)) {
            remove_all(run_folder, ec);
            if (ec) {
                log(LogLevel::ERROR, "Failed to clean last_run directory: %s: %s", run_folder.c_str(), ec.message().c_str());
                throw runtime_error("Unable to clean last_run directory");
            }
        }
        create_directories(run_folder, ec);
        if (ec) {
            log(LogLevel::ERROR, "Failed to create last_run directory: %s: %s",run_folder.c_str(), ec.message().c_str());
            throw runtime_error("Unable to create last_run directory");
        }

        save_actor_interface_mapping();
        process_manager.init_logging(run_folder);

        const auto module_name = config.at("attacker_module");
        const auto run_it = attack_module_maps::setup_map.find(module_name);

        if (run_it != attack_module_maps::setup_map.end()) {run_it->second(*this);
        } else {log(LogLevel::DEBUG, "setup function not set");}
    }
}