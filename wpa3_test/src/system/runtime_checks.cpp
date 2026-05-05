#include "logger/error_log.h"
#include "system/hw_capabilities.h"
#include "system/netlink_helper.h"

using namespace std;
using namespace Tins;

namespace wpa3_tester{
bool check_injection_runtime(const string &iface){
	hw_capabilities::set_wifi_type(iface, NL80211_IFTYPE_MONITOR, nullopt);
	if(const auto res = netlink_helper::wait_for_wifi_iftype(iface, nullopt, NL80211_IFTYPE_MONITOR); !res)
		throw req_err("Injection wait_for_wifi_iftype failed");
	hw_capabilities::set_iface_up(iface, nullopt);
	if(const auto res = netlink_helper::wait_for_link_flags(iface, nullopt, true); !res)
		throw req_err("Injection wait_for_link_flags failed");

	try{
		RadioTap rt;
		rt.inner_pdu(Dot11Data{});
		PacketSender{iface}.send(rt);
		return true;
	} catch(const socket_write_error &){
		return false;
	}
}
}