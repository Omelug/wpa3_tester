#include "config/RunStatus.h"
#include "logger/log.h"
#include "attacks/attacks.h"
#include <filesystem>

void RunStatus::setup_test(){

    namespace fs = std::filesystem;
    fs::path base = fs::current_path();
    fs::path data_root = base / "data" / "wpa3_test" / "run" / config["name"];
    fs::path last_run = data_root / "last_run";

    // Ensure parent directories exist
    std::error_code ec;
    fs::create_directories(data_root, ec);
    if (ec) {
        log(LogLevel::ERROR, "Failed to create run base directory: {}: {}", data_root.string(), ec.message());
        throw std::runtime_error("Unable to create run base directory");
    }

    // Recreate last_run directory empty
    if (fs::exists(last_run, ec)) {
        fs::remove_all(last_run, ec);
        if (ec) {
            log(LogLevel::ERROR, "Failed to clean last_run directory: {}: {}", last_run.string(), ec.message());
            throw std::runtime_error("Unable to clean last_run directory");
        }
    }
    fs::create_directories(last_run, ec);
    if (ec) {
        log(LogLevel::ERROR, "Failed to create last_run directory: {}: {}",last_run.string(), ec.message());
        throw std::runtime_error("Unable to create last_run directory");
    }

    // Store the path in RunStatus
    run_folder = last_run.string();

    // TODO  create process_logger

	// -------- INTERNAL --------------
	attack_setup[config["attacker_module"]](*this);

    /*for (const auto& [actor_name, actor] : internal_actors) {
        // setup monitor mode etc.

        //setup = config["actors"][actor_name]["setup"];

        // run processes
        /*if(config["actors"][actor_name]["type"] == "AP"){
            if(!config.contains("AP_program")){
                log(LogLevel::WARNING, "AP program not found -> default hostapd");
                run_process[config["AP_program"]]();
            }
            //TODO not deault AP defau
        }*/

		/*if(config["actors"][actor_name]["type"] == "STA"){
            if(!config.contains("STA_program")){
                log(LogLevel::WARNING, "AP program not found -> default hostapd");
                run_process[config["AP_program"]]();
            }
            //TODO not deault STA program
        }
    }*/
};