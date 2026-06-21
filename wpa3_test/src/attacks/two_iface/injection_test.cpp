#include "attacks/two_iface/injection_test.h"
#include <filesystem>
#include <linux/nl80211.h>
#include <tins/tins.h>

#include "default.h"
#include "attacks/mc_mitm/MonitorSocket.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "system/hw_capabilities.h"
#include "system/injection_result.h"
#include "system/utils.h"

namespace wpa3_tester{
using namespace std;
using namespace filesystem;
using namespace Tins;

static bool driver_needs_mf_workaround(const string &driver){
	return driver == "iwlwifi" || driver == "ath9k_htc" || driver == "rt2800usb";
}

static Dot11Ref make_spoofed_frame(){
	return {.addr1 = HWAddress<6>("00:11:00:00:02:01"), .addr2 = HWAddress<6>("00:22:00:00:02:01"), .from_ds = true};
}

static Dot11Ref make_valid_frame(const HWAddress<6> &peermac, const HWAddress<6> &ownmac){
	return {.addr1 = peermac, .addr2 = ownmac, .from_ds = true};
}

InjectionSuiteResult hw_capabilities::run_injection_tests(ActorPtr actor_tx, ActorPtr actor_rx,
														const HWAddress<6> &peermac, const bool skip_mf,
														const bool testack
){
	if(actor_tx->conn)
		throw not_implemented_err("Remote TX injection not supported (OpenWrt as actor_tx)");

	const bool rx_has_vif = actor_rx[SK::sniff_iface].has_value();
	const string cap_iface = rx_has_vif ? actor_rx.get(SK::sniff_iface) : actor_rx.get(SK::iface);

	MonitorSocket s_out(actor_tx.get(SK::iface), actor_tx[SK::netns]);
	MonitorSocket s_in = actor_rx->conn
		? MonitorSocket(actor_rx->conn->open_capture_channel(cap_iface))
		: MonitorSocket(cap_iface, actor_rx[SK::netns]);

	const Channel ch = actor_tx->get_channel();

	InjectionSuiteResult suite;
	suite.iface_out = actor_tx.get(SK::iface);;
	suite.iface_in = cap_iface;
	suite.channel = ch;
	suite.driver = actor_tx.get(SK::driver_name);

	s_out.mf_workaround = driver_needs_mf_workaround(suite.driver);

	const auto tx_mac = actor_tx.get(SK::mac); //get_mac_address(, actor_tx[SK::netns]);
	const auto spoofed = make_spoofed_frame();
	const auto valid = make_valid_frame(peermac, tx_mac);

	auto add = [&](InjectionTestResult r){ suite.tests.push_back(std::move(r)); };

	if(!skip_mf){
		add(test_injection_more_fragments(s_out, s_in, spoofed, "spoofed", ch));
		add(test_injection_more_fragments(s_out, s_in, valid, "valid", ch));
	}

	add(test_injection_fields(s_out, s_in, spoofed, "spoofed", ch));
	add(test_injection_fields(s_out, s_in, valid, "valid", ch));
	add(test_injection_order(s_out, s_in, spoofed, "spoofed", ch));
	add(test_injection_order(s_out, s_in, valid, "valid", ch));

	// retrans + txack only make sense with two distinct interfaces
	bool two_iface = cap_iface != actor_tx.get(SK::iface);;
	if(two_iface && testack){
		if(rx_has_vif){
			// receiver's main iface (managed/AP) HW-ACKs frames → no nearby AP needed
			const HWAddress<6> rx_mac(actor_rx.get(SK::mac));
			add(test_injection_retrans(s_out, s_in, rx_mac, tx_mac, ch));
			add(test_injection_txack(s_out, s_in, rx_mac, tx_mac, ch));
		} else{
			const auto nearby = get_nearby_ap_addr(s_in);
			const auto destmac = nearby ? nearby->first : peermac;
			add(test_injection_retrans(s_out, s_in, destmac, tx_mac, ch));
			if(nearby) add(test_injection_txack(s_out, s_in, destmac, tx_mac, ch));
		}
	}

	return suite;
}
}

namespace wpa3_tester::injection_test{
using namespace std;
using namespace filesystem;
using nlohmann::json;

void run_attack(RunStatus &rs){
	auto &actor_tx = rs.get_actor("transceiver");
	auto &actor_rx = rs.get_actor("receiver");

	const InjectionSuiteResult suite = hw_capabilities::run_injection_tests(actor_tx, actor_rx);

	const path result_path = rs.run_folder() / RESULT_NAME;
	{
		ofstream ofs(result_path);
		ofs << suite.to_json().dump(2);
	}
	set_public_perms(result_path);
}
}
