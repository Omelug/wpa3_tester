#include "config/global_config.h"
#include "config/RunStatus.h"
#include "observer/observers.h"
#include "setup/program.h"
#include "system/hw_capabilities.h"
#include "system/ip.h"

using namespace std;
using namespace filesystem;

namespace wpa3_tester::invalid_curve{

    void start_dragonslayer(RunStatus & rs, const string &actor_name, const string &iface, const string &target_type){
        assert(target_type == "ap" || target_type == "sta");
        vector<string> command = {};
        observer::add_nets(rs, command, actor_name);
        const string dragonslayer_folder = get_global_config().at("paths").at("dragonslayer").at("dragonslayer_folder");
        if(target_type == "ap"){
            command.insert(command.end(), {
              dragonslayer_folder+"/wpa_supplicant/wpa_supplicant",
              "-D", "nl80211",
              "-c", path(rs.run_folder)/"dragonslayer.conf",
              "-i", iface,
              "-a", "1"
          });
        }
        if(target_type == "sta"){
            command.insert(command.end(), {
             dragonslayer_folder+"/hostapd/hostapd",
             path(rs.run_folder)/"dragonslayer.conf",
             "-i", iface,
             "-a", "1"
         });
        }
        rs.process_manager.run(actor_name, command, path(dragonslayer_folder));
    }

    void setup_attack(RunStatus& rs){
        copy_file(path(rs.config_path).parent_path()/"config/hostapd.eap_user", path(rs.run_folder)/"hostapd.eap_user");
        copy_file(
            path(rs.config_path).parent_path()/"config/dragonslayer.conf",
            path(rs.run_folder)/"dragonslayer.conf"
            );

        // -------- AP
        program::start(rs, "access_point");
        rs.process_manager.wait_for("access_point", "AP-ENABLED", std::chrono::seconds(40));
        log(LogLevel::INFO, "access_point is running");
        ip::set_ip(rs, "access_point");

        // ---- attacker
        const auto attacker = rs.get_actor("attacker");
    }

    void run_attack(RunStatus& rs){
        const auto& att_cfg = rs.config.at("attack_config");
        const auto target_type = att_cfg.at("target_type").get<string>();
        const auto& attacker = rs.get_actor("attacker");

        if(target_type == "ap"){
            start_dragonslayer(rs, attacker["actor_name"], attacker["iface"],"ap");
            rs.process_manager.wait_for("attacker", "Server is vulnerable to invalid curve attack", chrono::seconds(40));
        }
        if(target_type == "sta"){
            start_dragonslayer(rs, attacker["actor_name"], attacker["iface"],"sta");
            program::start(rs, "client");

            size_t replay = 5;
            //TODO run multiple times (33% of fail)
            for(size_t i = 0; i < replay; i++){
                rs.process_manager.wait_for("client", "EVENT-CONNECTED", chrono::seconds(10));
                if(rs.process_manager.wait_for("attacker", "Client is vulnerable to invalid curve attack",
                    chrono::seconds(4), false)) break;
                    rs.process_manager.stop("client");

            }
        }

    }

    /*void stats(const RunStatus& rs){
    }*/
}
