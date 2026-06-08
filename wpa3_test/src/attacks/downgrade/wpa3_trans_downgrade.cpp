#include "attacks/downgrade/wpa3_trans_downgrade.h"
#include <chrono>
#include <fstream>
#include <nlohmann/json.hpp>
#include "inteprrupt.h"
#include "attacks/components/setup_connections.h"
#include "logger/log.h"
#include "logger/report.h"
#include "observer/tshark_wrapper.h"
#include "system/utils.h"

namespace wpa3_tester::wpa3_trans_downgrade {
using namespace std;
using namespace filesystem;
using namespace chrono;
using nlohmann::json;

void setup_attack(RunStatus &rs) {
	components::client_ap_setup(rs);
	components::setup_rogue_ap(rs);
}

void run_attack(RunStatus &rs) {
	const auto &att_cfg = rs.config().at("attack_config");
	const int wait_after_stop = att_cfg.value("wait_after_stop", 30);

	rs.start_observers();

	interruptible_sleep(seconds(5));
	if (g_interrupted.load()) return;

	log(LogLevel::INFO, "Stopping WPA3-Transition AP - watching if client downgrades to WPA2-PSK rogue AP");
	rs.process_manager.stop("access_point");

	const bool rogue_connected = rs.process_manager.wait_for(
		"rogue_ap", "AP-STA-CONNECTED", seconds(wait_after_stop), false
	);

	if (rogue_connected) {
		log(LogLevel::INFO, "Client associated with WPA2-PSK rogue AP - VULNERABLE to downgrade");
	} else {
		log(LogLevel::INFO, "Client did not connect to WPA2-PSK rogue AP within {}s - not vulnerable", wait_after_stop);
	}

	rs.process_manager.stop_all();
}

void stats_attack(const RunStatus &rs) {
	G_elms elements;

	rs.log_events(elements, {
		{"client",    "CTRL-EVENT-DISCONNECTED",    "DISCONN",       "red"},
		{"client",    "CTRL-EVENT-CONNECTED",       "CONN",          "green"},
		{"client",    "key_mgmt=WPA-PSK",           "WPA2-DOWNGRADE","red"},
		{"client",    START_tag,                    "START",         "black"},
		{"client",    END_tag,                      "END",           "black"},
		{"rogue_ap",  "AP-STA-CONNECTED",           "ROGUE-CONN",    "purple"},
		{"rogue_ap",  "EAPOL-4WAY-HS-COMPLETED",    "ROGUE-4WAY",    "orange"},
	});

	observer::tshark::pcap_events(rs, elements, {
		{"attacker", "wlan.fc.type_subtype == 4", "ProbeReq", "blue"},
	});

	const auto disc_times       = get_time_logs(rs, "client",   "CTRL-EVENT-DISCONNECTED");
	const auto rogue_sta_times  = get_time_logs(rs, "rogue_ap", "AP-STA-CONNECTED");
	const auto rogue_4way_times = get_time_logs(rs, "rogue_ap", "EAPOL-4WAY-HS-COMPLETED");
	// wpa_supplicant logs "key_mgmt=WPA-PSK" when completing auth with a PSK network
	const auto wpa2_auth_times  = get_time_logs(rs, "client",   "key_mgmt=WPA-PSK");

	const bool disconnected     = !disc_times.empty();
	const bool rogue_connected  = !rogue_sta_times.empty();
	const bool downgrade_seen   = !wpa2_auth_times.empty();

	const string client_graph  = observer::tshark::tshark_graph(rs, "client",   elements).string();
	const string rogue_graph   = observer::tshark::tshark_graph(rs, "rogue_ap", elements).string();
	const string att_graph     = observer::tshark::tshark_graph(rs, "attacker", elements).string();

	const path report_path = rs.run_folder() / "report.md";
	ofstream report(report_path);
	if (!report.is_open()) {
		log(LogLevel::ERROR, "Failed to create report.md");
	} else {
		report << "# WPA3 Security Test Report: WPA3 Transition Downgrade to WPA2-PSK\n\n";
		report << "A client connected to a WPA3-Transition AP (SAE+PSK) is disconnected by stopping "
		          "the legitimate AP. A rogue WPA2-PSK-only AP with the same SSID and credentials "
		          "is running. A vulnerable client will automatically associate using WPA2-PSK.\n\n";
		report::attack_config_table(report, rs);
		report::attack_mapping_table(report, rs);
		report << "## Results\n\n";
		report << "| Metric | Value |\n|--------|-------|\n";
		report << "| Client disconnected from legitimate AP | " << (disconnected ? "yes" : "no") << " |\n";
		report << "| Client connected to rogue AP | " << (rogue_connected ? "**yes**" : "no") << " |\n";
		report << "| WPA2-PSK downgrade observed on client | " << (downgrade_seen ? "**yes**" : "no") << " |\n";
		report << "| Rogue AP 4-way handshakes completed | " << rogue_4way_times.size() << " |\n";
		report << "| Vulnerable (downgrade to WPA2) | " << (rogue_connected ? "**yes**" : "no") << " |\n\n";
		report << "## Traffic\n";
		report << "### Client\n";
		report << "![Client graph](" << relative(client_graph, rs.run_folder()).string() << ")\n\n";
		report << "### Rogue AP (WPA2-PSK)\n";
		report << "![Rogue AP graph](" << relative(rogue_graph, rs.run_folder()).string() << ")\n\n";
		report << "### Attacker (probe capture)\n";
		report << "![Attacker graph](" << relative(att_graph, rs.run_folder()).string() << ")\n\n";
		report << "---\n";
		report.close();
		set_public_perms(report_path);
	}

	const json result = {
		{"disconnected",        disconnected},
		{"rogue_connected",     rogue_connected},
		{"downgrade_seen",      downgrade_seen},
		{"rogue_4way_count",    static_cast<int>(rogue_4way_times.size())},
		{"vulnerable",          rogue_connected},
	};
	rs.save_result(result);
}
}