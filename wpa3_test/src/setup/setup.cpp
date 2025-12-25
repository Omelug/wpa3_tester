#include "config/RunStatus.h"
#include "logger/log.h"
#include "attacks/attacks.h"

void RunStatus::setup_test(){
	attack_setup[config["attacker_module"]]();

    //TODO external/simulation
    // run process_logger
    // -------- INTERNAL --------------
    for (const auto& [actor_name, actor] : internal_actors) {
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
        }*/
    }
};