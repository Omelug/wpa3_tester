#include "attacks/two_iface/injection_test.h"
#include <filesystem>
#include <linux/nl80211.h>
#include <tins/tins.h>
#include "attacks/mc_mitm/MonitorSocket.h"
#include "config/RunStatus.h"
#include "system/hw_capabilities.h"
#include "system/injection_result.h"
#include "system/utils.h"

namespace wpa3_tester {
using namespace std;
using namespace filesystem;
using namespace Tins;


void hw_capabilities::setup_injection_iface(
	const string &iface, const Channel &ch, const optional<string> &netns
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
	ActorPtr actor_tx,
	ActorPtr actor_rx,
	const HWAddress<6> &peermac,
	const bool skip_mf,
	const bool testack
){

	auto if_out = actor_tx.get(SK::iface);
	auto if_in = actor_rx.get(SK::iface);
	MonitorSocket s_out(if_out, actor_tx[SK::netns]);
	MonitorSocket s_in(if_in, actor_rx[SK::netns]);
	const Channel ch = actor_tx->get_channel();

	InjectionSuiteResult suite;
	suite.iface_out = if_out;
	suite.iface_in  = if_in; // updated below for 2-iface case
	suite.channel   = ch;
	try{ suite.driver = get_driver_name(if_out, actor_tx[SK::netns]); } catch(...){}

	s_out.mf_workaround = driver_needs_mf_workaround(suite.driver);

	const auto ownmac  = get_mac_address(if_out, actor_tx[SK::netns]);
	const auto spoofed = make_spoofed();
	const auto valid   = make_valid(peermac, ownmac);

	auto add = [&](InjectionTestResult r){suite.tests.push_back(std::move(r));};

	if(!skip_mf){
		add(test_injection_more_fragments(s_out, s_in, spoofed, "spoofed", ch));
		add(test_injection_more_fragments(s_out, s_in, valid,   "valid",   ch));
	}

	add(test_injection_fields(s_out, s_in, spoofed, "spoofed", ch));
	add(test_injection_fields(s_out, s_in, valid,   "valid",   ch));
	add(test_injection_order(s_out, s_in, spoofed, "spoofed", ch));
	add(test_injection_order(s_out, s_in, valid,   "valid",   ch));

	// retrans + txack only make sense with two distinct interfaces
	bool two_iface = (if_in != if_out);
	if(two_iface && testack){
		//FIXME add these test to result a zbavit se závislosti na okolním AP
		const auto nearby = get_nearby_ap_addr(s_in);
		const auto destmac = nearby ? nearby->first : peermac;
		add(test_injection_retrans(s_out, s_in, destmac, ownmac, ch));
		if(nearby)
			add(test_injection_txack(s_out, s_in, destmac, ownmac, ch));
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

	const InjectionSuiteResult suite = hw_capabilities::run_injection_tests(actor_tx, actor_rx);

	const path result_path = rs.run_folder() / "result.json";
	{
		ofstream ofs(result_path);
		ofs << suite.to_json().dump(2);
	}
	set_public_perms(result_path);
}

}
