#include "config/global_config.h"
#include "config/RunStatus.h"
#include "observer/observers.h"
#include "setup/program.h"
#include "system/hw_capabilities.h"
#include "system/ip.h"

using namespace std;
using namespace filesystem;

namespace wpa3_tester::invalid_curve{

    void start_dragonslayer(RunStatus & rs, const string &actor_name, const string &iface){
        vector<string> command = {"sudo"};
        observer::add_nets(rs, command, actor_name);
        const string dragonslayer_folder = get_global_config().at("paths").at("dragonslayer").at("dragonslayer_folder");
        // TODO compile dragonslayer, if not compiled
        command.insert(command.end(), {
            dragonslayer_folder+"/dragonslayer-server.sh",
            "-i", iface,
            "-a", "1"
        });
        rs.process_manager.run(actor_name, command, path(dragonslayer_folder));
    }

    void setup_attack(RunStatus& rs){
        copy_file(path(rs.config_path).parent_path()/"hostapd.eap_user", path(rs.run_folder)/"hostapd.eap_user");

        // -------- AP
        program::start(rs, "access_point");
        rs.process_manager.wait_for("access_point", "AP-ENABLED", std::chrono::seconds(40));
        log(LogLevel::INFO, "access_point is running");
        ip::set_ip(rs, "access_point");

        // ---- attacker
        const auto attacker = rs.get_actor("attacker");
        start_dragonslayer(rs, attacker["actor_name"], attacker["iface"]);
    }

    void run_attack(RunStatus& rs){
        // ----- connect STA
        program::start(rs, "client");
        rs.process_manager.wait_for("client", "Successfully initialized wpa_supplicant", std::chrono::seconds(10));
        ip::set_ip(rs, "client");
        rs.process_manager.wait_for("client", "EVENT-CONNECTED", chrono::seconds(40));
        rs.process_manager.wait_for("access_point", "AP-STA-CONNECTED", chrono::seconds(40));
        log(LogLevel::INFO, "client is connected");
        rs.process_manager.wait_for("attacker", "Client is vulnerable to invalid curve attack", chrono::seconds(10));
        //FIXME run multiple times (33% of fail)
    }

    /*void stats(const RunStatus& rs){
    }*/
}
