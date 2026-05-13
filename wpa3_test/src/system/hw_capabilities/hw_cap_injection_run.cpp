#include "system/hw_capabilities.h"
#include <linux/nl80211.h>
#include <tins/tins.h>
#include "attacks/mc_mitm/MonitorSocket.h"
#include "system/injection_result.h"

namespace wpa3_tester{
using namespace std;
using namespace Tins;

// -----------------
void hw_capabilities::setup_injection_iface(
	const string &iface, const int channel, const optional<string> &netns
){
	set_iface_down(iface, netns);
	set_wifi_type(iface, NL80211_IFTYPE_MONITOR, netns);
	set_iface_up(iface, netns);
	set_channel(iface, channel, netns);
}

// -----------------
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

// -----------------
InjectionSuiteResult hw_capabilities::run_injection_tests(
	MonitorSocket &sout, const string &iface_out,
	MonitorSocket &sin,
	const int channel,
	const HWAddress<6> &peermac,
	const bool skip_mf,
	const bool testack
){
	InjectionSuiteResult suite;
	suite.iface_out = iface_out;
	suite.iface_in  = iface_out; // updated below for 2-iface case
	suite.channel   = channel;
	try{ suite.driver = get_driver_name(iface_out); } catch(...){}

	sout.mf_workaround = driver_needs_mf_workaround(suite.driver);

	const auto ownmac  = get_macaddress(iface_out, nullopt);
	const auto spoofed = make_spoofed();
	const auto valid   = make_valid(peermac, ownmac);

	auto add = [&](InjectionTestResult r){ suite.tests.push_back(std::move(r)); };

	if(!skip_mf){
		add(test_injection_more_fragments(sout, sin, spoofed, "spoofed", channel));
		add(test_injection_more_fragments(sout, sin, valid,   "valid",   channel));
	}

	add(test_injection_fields(sout, sin, spoofed, "spoofed", channel));
	add(test_injection_fields(sout, sin, valid,   "valid",   channel));
	add(test_injection_order (sout, sin, spoofed, "spoofed", channel));
	add(test_injection_order (sout, sin, valid,   "valid",   channel));

	// retrans + txack only make sense with two distinct interfaces
	const bool two_iface = (&sout != &sin);
	if(two_iface && testack){
		const auto nearby = get_nearby_ap_addr(sin);
		const auto destmac = nearby ? nearby->first : peermac;
		add(test_injection_retrans(sout, sin, destmac, ownmac, channel));
		if(nearby)
			add(test_injection_txack(sout, sin, destmac, ownmac, channel));
	}

	return suite;
}

}
