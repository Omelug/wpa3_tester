#include "system/hw_capabilities.h"

using namespace std;
using namespace Tins;

namespace wpa3_tester{
bool check_injection_runtime(const string &iface_name){
	Actor_config actor{};
	actor[SK::iface] = iface_name;
	actor.set_monitor_mode();
	actor.set_iface_up();

	this_thread::sleep_for(chrono::seconds(5));

	try{
		RadioTap rt;
		rt.inner_pdu(Dot11Data()); // minimal Null-Data frame

		PacketSender sender(iface_name);
		sender.send(rt);
		return true;
	} catch(const socket_write_error &){
		return false;
	}
}
}