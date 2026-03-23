#include "attacks/attacks.h"

#include "attacks/by_target/scan_AP.h"
#include "attacks/components/setup_connections.h"
#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "attacks/DoS_hard/cookie_guzzler/test_sae_commit_monitor/test_sae_commit_monitor.h"
#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "attacks/DoS_soft/malformed_eapol1/malformed_eapol1.h"
#include "attacks/DoS_soft/bl0ck/bl0ck.h"
#include "attacks/DoS_soft/bl0ck/test_monitor_bl0ck/test_sae_commit_monitor.h"
#include "attacks/Enterprise/invalid_curve.h"
#include "attacks/Enterprise/reflection_attack.h"

namespace wpa3_tester::attack_module_maps{
    using namespace std;

    map<string, function<void(RunStatus&)>> setup_map = {
        {"channel_switch", CSA_attack::setup_chs_attack},
        {"bl0ck", components::client_ap_attacker_setup},
        {"malformed_eapol1", components::client_ap_attacker_setup},
        {"cookie_guzzler", components::client_ap_attacker_setup},
        {"reflection_attack", reflection::setup_attack},
        {"invalid_curve", invalid_curve::setup_attack},
    };

    map<string, function<void(RunStatus&)>> run_map = {
        {"channel_switch", CSA_attack::run_chs_attack},
        {"bl0ck", bl0ck_attack::run_bl0ck_attack},
        {"bl0ck_monitor_test", test_monitor_bl0ck::run_attack},
        {"sae_commit_monitor_test", test_sae_commit_monitor::run_attack},
        {"malformed_eapol1", eapol_logoff::run_attack},
        {"cookie_guzzler", cookie_guzzler::run_attack},
        {"reflection_attack", reflection::run_attack},
        {"invalid_curve", invalid_curve::run_attack},
        {"scan_AP", attack_scan::run_attack}
    };

    map<string, function<void(const RunStatus&)>> stats_map = {
        {"channel_switch", CSA_attack::stats_chs_attack},
        {"bl0ck", bl0ck_attack::stats_bl0ck_attack},
        {"bl0ck_monitor_test", test_monitor_bl0ck::stats_attack},
        {"sae_commit_monitor_test", test_sae_commit_monitor::stats_attack},
        {"malformed_eapol1", eapol_logoff::stats},
        {"cookie_guzzler", cookie_guzzler::stats_attack},
        //{"reflection_attack", reflection::stats}
        //{"invalid_curve", invalid_curve::run_attack}
    };
}
