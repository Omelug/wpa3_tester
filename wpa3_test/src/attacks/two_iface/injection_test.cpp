#include "attacks/two_iface/injection_test.h"
#include <filesystem>
#include <linux/nl80211.h>
#include <tins/tins.h>

#include "attacks/mc_mitm/MonitorSocket.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "config/RunStatus.h"
#include "default.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "system/hw_capabilities.h"
#include "system/injection_result.h"
#include "system/utils.h"

namespace wpa3_tester {
using namespace std;
using namespace filesystem;
using namespace Tins;

static bool driver_needs_mf_workaround(const string &driver) {
	//TODO this need to be used in actual test in attacks where MF used
	return driver == "iwlwifi" || driver == "ath9k_htc" || driver == "rt2800usb";
}

static Dot11Ref make_spoofed_frame() {
	return { .addr1 = HWAddress<6>("00:11:00:00:02:01"), .addr2 = HWAddress<6>("00:22:00:00:02:01"), .from_ds = true };
}

static Dot11Ref make_valid_frame(const HWAddress<6> &peermac, const HWAddress<6> &ownmac) {
	return { .addr1 = peermac, .addr2 = ownmac, .from_ds = true };
}

InjectionSuiteResult hw_capabilities::run_injection_tests(
		ActorPtr actor_tx, ActorPtr actor_rx, const HWAddress<6> &peermac, const bool testack, RunStatus *rs) {
	const string cap_iface = actor_rx[BK::sniff_iface] ? actor_rx.get_mon_iface() : actor_rx.get(SK::iface);

	MonitorSocket s_out = actor_tx->conn
			? MonitorSocket(actor_tx->conn->open_inject_channel(actor_tx.get(SK::iface)), MonitorSocket::tag_tx_t{})
			: MonitorSocket(actor_tx.get(SK::iface), actor_tx[SK::netns]);
	MonitorSocket s_in = actor_rx->conn ? MonitorSocket(actor_rx->conn->open_capture_channel(cap_iface))
										: MonitorSocket(cap_iface, actor_rx[SK::netns]);

	const Channel ch = actor_tx->get_channel();

	InjectionSuiteResult suite;
	suite.iface_out = actor_tx.get(SK::iface);
	suite.iface_in = cap_iface;
	suite.channel = ch;
	suite.driver = actor_tx.get(SK::driver_name);
	suite.tx_mac = actor_tx.get(SK::mac);
	suite.rx_mac = actor_rx.get(SK::mac);
	suite.rx_driver = actor_rx->get_or(SK::driver_name, "");

	s_out.mf_workaround = driver_needs_mf_workaround(suite.driver);

	const auto tx_mac = suite.tx_mac;
	const auto spoofed = make_spoofed_frame();
	const auto valid = make_valid_frame(peermac, tx_mac);

	auto add = [&](InjectionTestResult r) { suite.tests.push_back(std::move(r)); };

	// more frame
	add(test_injection_more_fragments(s_out, s_in, spoofed, "spoofed", ch));
	add(test_injection_more_fragments(s_out, s_in, valid, "valid", ch));

	// injection filed
	add(test_injection_fields(s_out, s_in, spoofed, "spoofed", ch));
	add(test_injection_fields(s_out, s_in, valid, "valid", ch));

	//correct order of fragments
	add(test_injection_order(s_out, s_in, spoofed, "spoofed", ch));
	add(test_injection_order(s_out, s_in, valid, "valid", ch));

	// retrans + txack only make sense with two distinct interfaces
	bool two_iface = cap_iface != actor_tx.get(SK::iface);

	if(two_iface && testack && actor_rx->get_or(BK::AP, false)) {
		const string ap_vif = actor_rx.get_ap_iface();
		start_ap_hostapd(*rs, ap_vif, actor_rx, ch, HWAddress<6>(actor_rx.get(SK::mac)));

		// set_wifi_type fallback (del+recreate) may assign a new MAC to ap_vif - read actual MAC
		const HWAddress<6> ap_mac = get_mac_address(ap_vif, actor_rx[SK::netns]);

		// pcap handles survive iface down/up on Linux - reuse s_in, just flush stale buffer
		flush_socket(s_in);
		add(test_injection_retrans(s_out, s_in, ap_mac, tx_mac, ch));
		add(test_injection_txack(s_out, s_in, ap_mac, tx_mac, ch));

		rs->process_manager.stop(ap_vif + "_hostapd");
		run_cmd({"iw", "dev", ap_vif, "del"}, actor_rx[SK::netns], false);
	}

	return suite;
}
}

namespace wpa3_tester::injection_test {
using namespace std;
using namespace filesystem;
using nlohmann::json;

void run_attack(RunStatus &rs) {
	auto &actor_tx = rs.get_actor("transceiver");
	auto &actor_rx = rs.get_actor("receiver");
	rs.start_observers();
	const InjectionSuiteResult suite = hw_capabilities::run_injection_tests(actor_tx, actor_rx, {}, true, &rs);

	const path result_path = rs.run_folder() / RESULT_NAME;
	ofstream ofs(result_path);
	ofs << suite.to_json().dump(2);
	ofs.close();
	set_public_perms(result_path);
}
}