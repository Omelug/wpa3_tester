#include <filesystem>
#include "suite/DoS_soft/channel_switch/channel_switch_rogueAP.h"
#include "default.h"
#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "ex_program/external_actors/openwrt/openwrt_helper.h"
#include "logger/log_util.h"
#include "logger/report.h"
#include "observer/tshark_wrapper.h"
#include "overview/html_guard.h"
#include "suite/result_helper.h"
#include "suite/suite_helper.h"

namespace wpa3_tester::suite::channel_switch_rogueAP{
using namespace std;
using namespace filesystem;

CsaTestEntry parse_test_folder(const path &test_folder){
	auto e = helper::load_result_default<CsaTestEntry>(test_folder);
	e.name = test_folder.filename().string();

	const auto cfg_path = test_folder / TEST_CONFIG_NAME;
	const auto rs = helper::load_test_rs(test_folder); //FIXME error on currupted test, stop (checkall load_test_rs)
	const auto ap = rs->get_actor("ap");
	e.ap_mac = ap->get(SK::mac);
	e.ap_source = ap->get(SK::source);

	const auto client = rs->get_actor("client");
	//FIXME add mac to config/mapping to get it here in report (if client is external)
	e.client_mac = client->get(SK::mac);
	e.client_source = client->get(SK::source);
	auto program_str = rs->config().at("actors").at("ap").at("setup").at("program").get<string>();

	if(exists(test_folder / "client_wpa_supplicant.conf")){
		e.client_ocv +=  {hostapd::get_ocv(*rs, "client").value_or(false), "wpa_supplicant_conf"};
		e.client_mfp += {hostapd::get_mfp_from_supplicant(test_folder / "client_wpa_supplicant.conf"), "wpa_supplicant_conf"};
		e.client_WPA_support += {hostapd::get_conf_value(test_folder / "client_wpa_supplicant.conf", {"key_mgmt"}), "wpa_supplicant_conf"};
	}

	if(exists(test_folder / "ap_hostapd.conf")){
		e.ap_ocv += {hostapd::get_okc(*rs, "ap").value_or(false), "hostapd_conf"};
		if(program_str == "hostapd"){
			e.ap_WPA_support += {hostapd::get_conf_value(test_folder / "ap_hostapd.conf", {"wpa_key_mgmt"}), "hostapd_conf"};
		}
		if(program_str == "openwrt"){ //TODO hostapd parsiong ok ?
			e.ap_WPA_support += {hostapd::get_conf_value(test_folder / "ap_hostapd.conf", {"wpa_key_mgmt"}), "openwrt"};
		}
	}

	const path ap_log = test_folder / "logger" / "ap.log";
	if(exists(ap_log)){
		if(program_str == "hostapd"){
			e.conn_WPA_version += {hostapd::akm_from_ap_log(ap_log, START_tag), "hostapd"};
			if(e.client_mfp.value().empty())
				e.client_mfp += {hostapd::mfp_from_ap_log(ap_log, START_tag), "hostapd"};
			if(e.client_WPA_support.value().empty())
				e.client_WPA_support += {hostapd::client_akm_from_ap_log(ap_log, START_tag), "hostapd"};
		}
		if(program_str == "openwrt"){
			e.conn_WPA_version += {openwrt::akm_from_openwrt_log(ap_log, START_tag), "openwrt"};
			if(e.client_mfp.value().empty())
				e.client_mfp += {openwrt::mfp_from_openwrt_log(ap_log, START_tag), "openwrt"};
		}
	}

	const path attacker_pcap =  test_folder / "observer" / "tshark" / "attacker_capture.pcap";
	/*FIXME add beacon protection column
	 *if(){
		attacker_pcap.beacon_prot = ;
	}*/
	if(e.conn_WPA_version.value().empty())
		e.conn_WPA_version += {observer::tshark::akm_from_pcap(attacker_pcap), "attacker pcap"};

	if(e.client_ocv.empty())
		if(const auto v = observer::tshark::client_ocv_from_pcap(attacker_pcap))
			e.client_ocv += {*v, "pcap (probe req)"};

	if(e.ap_ocv.empty())
		if(const auto v = observer::tshark::ap_ocv_from_pcap(attacker_pcap))
			e.ap_ocv += {*v, "pcap (beacon)"};

	{
		LogTimePoint start_tp, end_tp;
		const path log_for_time = test_folder / "logger" / "rogue_ap.log";
		if(exists(log_for_time)){
			start_tp = get_tag_time(log_for_time, START_tag);
			end_tp = get_tag_time(log_for_time, END_tag);
		}
		if(const string ch = observer::tshark::client_scanning_from_pcap(attacker_pcap, e.client_mac, start_tp, end_tp); !ch.empty())
			e.client_scanning += {ch, "attacker pcap"};
	}

	if(const string ch = hostapd::client_scanning_from_ap_log(test_folder / "logger" / "ap.log", e.client_mac); !ch.empty())
		e.client_scanning += {ch, "ap log"};

	const auto att = rs->get_actor("attacker");
	e.attacker_mac = att->get(SK::mac);
	e.attacker_driver = att->get(SK::driver_name);

	if(const auto rogue = rs->actor("rogue_ap")){
		e.rogue_ap_mac = rogue->get(SK::mac);
		e.rogue_ap_driver = rogue->get(SK::driver_name);
	}

	const path tshark = test_folder / "observer" / "tshark";
	if(const auto p = tshark / "client_graph.png"; exists(p)) e.client_graph = p;
	if(const auto p = tshark / "ap_graph.png"; exists(p)) e.ap_graph = p;

	return e;
}

void render_table(overview::HtmlGuard &f, const vector<path> &folders, const path &page_dir) {
	f << "        <table class=\"aggregate\">\n"
	  << "            <thead><tr>"
	  << "<th>Test</th><th>AP MAC (source)</th><th>Client MAC (source)</th>"
	  << "<th>Attacker (driver)</th>"
	  << "<th>Disconnected?</th>"
	  << "<th>Rogue AP?</th>"
	  << "<th>Client MFP</th>"
	  << "<th>Scanning</th>"
	  << "</tr></thead>\n            <tbody>\n";
	for (const auto &p : folders) {
		const auto e = parse_test_folder(p);
		f << "                <tr>\n"
		  << "                    <td>" << overview::test_name_cell(p, e.name, page_dir) << "</td>\n"
		  << "                    <td>" << overview::device(e.ap_mac, page_dir) << " (" << e.ap_source << ")</td>\n"
		  << "                    <td>" << overview::device(e.client_mac, page_dir) << " (" << e.client_source << ")</td>\n"
		  << "                    <td>" << overview::device(e.attacker_mac, page_dir) << " (" << e.attacker_driver << ")</td>\n"
		  << "                    <td>" << e.disconnected << "</td>\n"
		  << "                    <td>" << e.rogue_ap_connected << "</td>\n"
		  << "                    <td>" << e.client_mfp << "</td>\n"
		  << "                    <td>" << e.client_scanning << "</td>\n"
		  << "                </tr>\n";
	}
	f << "            </tbody>\n        </table>\n";
}

void generate_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	const auto entries = helper::collect_entries_nested(run_dir, [&run_dir](const path &p){
		auto e = parse_test_folder(p);
		e.rel_path = relative(p, run_dir);
		return e;
	});

	report::ReportGuard report(run_dir);
	if(!report) return;

	report << "# CSA Rogue AP Test Suite Report\n\n";
	report << "Summary of Channel Switch + Rogue AP downgrade attack tests.\n\n";

	if(entries.empty()){ report << "No test results found.\n"; return; }

	report << "## Test Results\n\n";
	report << "| Test | AP MAC (source) | Client MAC (source) | Attacker MAC (driver) | Disconnected? (from_AP_view) ? | Rogue AP? | AP OCV / Client OCV | Client MFP | Result |\n";
	report << "|------|-----------------|---------------------|-----------------------|--------------------------------|-----------|---------------------|------------|--------|\n";

	for(const auto &e: entries){
		string attacker_cell = e.attacker_mac + " (" + e.attacker_driver + ")";
		if(!e.rogue_ap_mac.empty() || !e.rogue_ap_driver.empty())
			attacker_cell += "<br>" + e.rogue_ap_mac + " (" + e.rogue_ap_driver + ")";
		const string result_text = e.rogue_ap_connected ? (*e.rogue_ap_connected ? "PASSED" : "FAILED") : "N/A";

		report << "| " << report::link(e.name, e.rel_path / REPORT_NAME) << " | "
			<< e.ap_mac << " (" << e.ap_source << ") | "
			<< e.client_mac << " (" << e.client_source << ") | "
			<< attacker_cell << " | "
			<< e.disconnected << " (" << e.ap_disconnected << ") | "
			<< e.rogue_ap_connected << " | "
			<< e.ap_ocv << " / " << e.client_ocv << " | "
			<< e.client_mfp << " | "
			<< report::link(result_text, e.rel_path / RESULT_NAME) << " |\n";
	}

}
}
