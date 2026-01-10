#include "config/RunStatus.h"
#include "logger/log.h"
#include "attacks/attacks.h"
#include <filesystem>

namespace wpa3_tester{
    using namespace std;
    void RunStatus::setup_test(){
        namespace fs = filesystem;
        // Recreate last_run directory empty
        error_code ec;
        if (fs::exists(run_folder, ec)) {
            fs::remove_all(run_folder, ec);
            if (ec) {
                log(LogLevel::ERROR, "Failed to clean last_run directory: %s: %s", run_folder.c_str(), ec.message().c_str());
                throw runtime_error("Unable to clean last_run directory");
            }
        }
        fs::create_directories(run_folder, ec);
        if (ec) {
            log(LogLevel::ERROR, "Failed to create last_run directory: %s: %s",run_folder.c_str(), ec.message().c_str());
            throw runtime_error("Unable to create last_run directory");
        }

        save_actor_interface_mapping();
        process_manager.init_logging(run_folder);
        attack_setup[config["attacker_module"]](*this);
    }
}