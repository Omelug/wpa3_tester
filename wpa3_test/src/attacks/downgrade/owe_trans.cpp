#include "attacks/downgrade/owe_trans.h"
#include <atomic>
#include <chrono>
#include <fstream>
#include <thread>
#include <nlohmann/json.hpp>
#include <tins/tins.h>
#include "inteprrupt.h"
#include "attacks/components/setup_connections.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/log.h"
#include "logger/report.h"
#include "observer/tshark_wrapper.h"
#include "system/utils.h"

namespace wpa3_tester::owe_trans {
using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;
using nlohmann::json;

void setup_attack(RunStatus &rs) {
	components::client_ap_setup(rs);
}

void run_attack(RunStatus &rs) {
	const auto &att_cfg = rs.config().at("attack_config");
	const int probe_wait_time = att_cfg.value("probe_wait_time", 30);

	const string sta_mac_str = rs.get_actor("client")["mac"];
	const string attacker_iface = rs.get_actor("attacker")["iface"];

	rs.start_observers();

	log(LogLevel::INFO, "Stopping AP - waiting for client probe requests");
	components::setup_rogue_ap(rs);
	rs.process_manager.stop("access_point");

	atomic probe_count{0};
	atomic stop_sniff{false};

	SnifferConfiguration sniff_cfg;
	sniff_cfg.set_promisc_mode(true);
	sniff_cfg.set_immediate_mode(true);
	sniff_cfg.set_filter("wlan type mgt subtype probe-req and wlan src " + sta_mac_str);

	Sniffer sniffer(attacker_iface, sniff_cfg);
	thread sniff_thread([&] {
		sniffer.sniff_loop([&](PDU &) -> bool {
			if (stop_sniff.load()) return false;
			const int n = ++probe_count;
			log(LogLevel::INFO, "Probe request from client (count: {})", n);
			return true;
		});
	});

	interruptible_sleep(seconds(probe_wait_time));
	stop_sniff.store(true);
	sniffer.stop_sniff();
	sniff_thread.join();

	log(LogLevel::INFO, "Total probe requests detected: {}", probe_count.load());
	rs.process_manager.stop_all();
}

void stats_attack(const RunStatus &rs) {
	G_elms elements;

	rs.log_events(elements, {
		{"client", "CTRL-EVENT-DISCONNECTED",   "DISCONN",    "red"},
		{"client", "CTRL-EVENT-SCAN-STARTED",   "SCAN",       "orange"},
		{"client", START_tag,                   "START",      "black"},
		{"client", END_tag,                     "END",        "black"},
	});

	observer::tshark::pcap_events(rs, elements, {
		{"attacker", "wlan.fc.type_subtype == 4", "ProbeReq", "blue"},
	});

	optional<hostapd::CrackResult> crack_result;
	if (rs.config().at("actors").contains("rogue_ap")) {
		elements.push_back(make_unique<EventLines>(get_time_logs(rs, "rogue_ap", "Captured a WPA"), "MANA", "black"));

		const string psk = hostapd::get_password(rs, "client");
		if (!psk.empty())
			crack_result = hostapd::crack_pmk_hashes(rs.run_folder() / "captured_hashes.txt", psk);
	}

	const auto probe_times = observer::tshark::get_tshark_events(rs, "attacker",
		"wlan.fc.type_subtype == 4", "ProbeReq");
	const int probe_count = static_cast<int>(probe_times.size());

	const auto disc_times = get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED", true);
	const bool disconnected = !disc_times.empty();

	const string client_graph  = observer::tshark::tshark_graph(rs, "client", elements).string();
	const string attacker_graph = observer::tshark::tshark_graph(rs, "attacker", elements).string();

	const path report_path = rs.run_folder() / "report.md";
	ofstream report(report_path);
	if (!report.is_open()) {
		log(LogLevel::ERROR, "Failed to create report.md");
	} else {
		report << "# WPA3 Security Test Report: OWE Transition Probe Leak\n\n";
		report << "After stopping the OWE AP, a client with autoconnect will emit probe requests "
		          "to rediscover the network, potentially revealing its preferred SSID list.\n\n";
		report::attack_config_table(report, rs);
		report::attack_mapping_table(report, rs);
		report << "## Results\n\n";
		report << "| Metric | Value |\n|--------|-------|\n";
		report << "| Client disconnected | " << (disconnected ? "yes" : "no") << " |\n";
		report << "| Probe requests detected | " << probe_count << " |\n";
		report << "| Vulnerable (probes sent) | " << (probe_count > 0 ? "yes" : "no") << " |\n\n";
		if (crack_result.has_value()) {
			report << "## Credential Capture (hcxpmktool)\n";
			report << "Each captured handshake was verified against the known PSK using hcxpmktool.\n\n";
			report << "| Metric | Value |\n|--------|-------|\n";
			report << "| Captured handshakes | " << crack_result->total << " |\n";
			report << "| Successfully cracked | " << crack_result->cracked << " |\n\n";
		}
		report << "## Traffic\n";
		report << "### Client\n";
		report << "![Client graph](" << relative(client_graph, rs.run_folder()).string() << ")\n\n";
		report << "### Attacker (probe capture)\n";
		report << "![Attacker graph](" << relative(attacker_graph, rs.run_folder()).string() << ")\n\n";
		if (rs.config().at("actors").contains("rogue_ap")) {
			const string rogue_graph = observer::tshark::tshark_graph(rs, "rogue_ap", elements).string();
			report << "### Rogue AP\n";
			report << "![Rogue AP graph](" << relative(rogue_graph, rs.run_folder()).string() << ")\n\n";
		}
		report << "---\n";
		report.close();
		set_public_perms(report_path);
	}

	const json result = {
		{"disconnected",            disconnected},
		{"disconnect_count",        static_cast<int>(disc_times.size())},
		{"probe_requests_detected", probe_count},
		{"vulnerable",              probe_count > 0},
	};
	rs.save_result(result);
}
}