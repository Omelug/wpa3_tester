#include "attacks/components/setup_connections.h"
#include "config/global_config.h"
#include "config/RunStatus.h"
#include "observer/observers.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace filesystem;

namespace wpa3_tester::reflection{
    void setup_attack(RunStatus& rs){
        copy_file(path(rs.config_path).parent_path()/"hostapd.eap_user", path(rs.run_folder)/"hostapd.eap_user");
        components::client_ap_attacker_setup_enterprise(rs);
    }

    void start_dragonslayer(RunStatus & rs, const string &actor_name, const string &iface){
        vector<string> command = {"sudo"};
        observer::add_nets(rs, command, actor_name);
        const string dragonslayer_folder = get_global_config().at("paths").at("dragonslayer").at("dragonslayer_folder");
        // TODO compile dragonslayer, if not compiled
        command.insert(command.end(), {
            dragonslayer_folder+"/dragonslayer-client.sh",
            "-i", iface,
            "-a", "0"
        });
        rs.process_manager.run(actor_name, command, path(dragonslayer_folder));
    }

    void run_attack(RunStatus& rs){
        const auto attacker = rs.get_actor("attacker");
        start_dragonslayer(rs, attacker["actor_name"], attacker["iface"]);
        this_thread::sleep_for(chrono::seconds(100));
    }
    /*void stats(const RunStatus& rs){
    }*/
}
