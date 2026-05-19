#include "attacks/two_iface/injection_test.h"
#include <fstream>
#include <filesystem>
#include <linux/nl80211.h>
#include <tins/tins.h>
#include "config/RunStatus.h"
#include "config/actor_keys.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "attacks/mc_mitm/MonitorSocket.h"
#include "system/injection_result.h"

namespace wpa3_tester {
using namespace std;
using namespace filesystem;
using namespace Tins;


void hw_capabilities::setup_injection_iface(
	const string &iface, const Channel ch, const optional<string> &netns
){
	set_iface_down(iface, netns);
	set_wifi_type(iface, NL80211_IFTYPE_MONITOR, netns);
	set_iface_up(iface, netns);
	set_channel(iface, ch, netns);
}


static bool driver_needs_mf_workaround(const string &driver){
	return driver == "iwlwifi" || driver == "ath9k_htc" || driver == "rt2800usb";
}

static Dot11Ref make_spoofed(){
	return {
		.addr1 = HWAddress<6>("00:11:00:00:02:01"),
		.addr2 = HWAddress<6>("00:22:00:00:02:01"),
		.from_ds = true
	};
}

static Dot11Ref make_valid(const HWAddress<6> &peermac, const HWAddress<6> &ownmac){
	return { .addr1 = peermac, .addr2 = ownmac, .from_ds = true };
}


InjectionSuiteResult hw_capabilities::run_injection_tests(
	MonitorSocket &sout, const string &iface_out,
	MonitorSocket &sin,
	const Channel ch,
	const HWAddress<6> &peermac,
	const bool skip_mf,
	const bool testack
){
	InjectionSuiteResult suite;
	suite.iface_out = iface_out;
	suite.iface_in  = iface_out; // updated below for 2-iface case
	suite.channel   = ch;
	try{ suite.driver = get_driver_name(iface_out); } catch(...){}

	sout.mf_workaround = driver_needs_mf_workaround(suite.driver);

	const auto ownmac  = get_mac_address(iface_out, nullopt);
	const auto spoofed = make_spoofed();
	const auto valid   = make_valid(peermac, ownmac);

	auto add = [&](InjectionTestResult r){suite.tests.push_back(std::move(r));};

	if(!skip_mf){
		add(test_injection_more_fragments(sout, sin, spoofed, "spoofed", ch));
		add(test_injection_more_fragments(sout, sin, valid,   "valid",   ch));
	}

	add(test_injection_fields(sout, sin, spoofed, "spoofed", ch));
	add(test_injection_fields(sout, sin, valid,   "valid",   ch));
	add(test_injection_order(sout, sin, spoofed, "spoofed", ch));
	add(test_injection_order(sout, sin, valid,   "valid",   ch));

	// retrans + txack only make sense with two distinct interfaces
	const bool two_iface = (&sout != &sin);
	if(two_iface && testack){
		const auto nearby = get_nearby_ap_addr(sin);
		const auto destmac = nearby ? nearby->first : peermac;
		add(test_injection_retrans(sout, sin, destmac, ownmac, ch));
		if(nearby)
			add(test_injection_txack(sout, sin, destmac, ownmac, ch));
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

	const string iface1 = actor_tx.get(SK::iface);
	const string iface2 = actor_rx.get(SK::iface);
	const Channel ch = actor_tx->get_channel();

	hw_capabilities::setup_injection_iface(iface1, ch, actor_tx[SK::netns]);
	hw_capabilities::setup_injection_iface(iface2, ch, actor_rx[SK::netns]);

	MonitorSocket s_out(iface1, actor_tx[SK::netns]);
	MonitorSocket s_in(iface2, actor_rx[SK::netns]);

	const InjectionSuiteResult suite = hw_capabilities::run_injection_tests(s_out, iface1, s_in, ch);

	const path result_path = rs.run_folder() / "result.json";
	ofstream ofs(result_path);
	ofs << suite.to_json().dump(2);
}

}
