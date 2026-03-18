#include "attacks/attacks.h"

#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "attacks/DoS_soft/malformed_eapol1/malformed_eapol1.h"
#include "attacks/DoS_soft/bl0ck/bl0ck.h"
#include "attacks/DoS_soft/bl0ck/test_monitor_bl0ck/test_monitor_bl0ck.h"

namespace wpa3_tester::attack_module_maps{
    using namespace std;

    map<string, function<void(RunStatus&)>> setup_map = {
        {"channel_switch", CSA_attack::setup_chs_attack},
        {"bl0ck", bl0ck_attack::setup_attack},
        //{"bl0ck_monitor_test", test_monitor_bl0ck::setup_attack},
        {"malformed_eapol1", CSA_attack::setup_chs_attack},
        {"cookie_guzzler", CSA_attack::setup_chs_attack},
    };

    map<string, function<void(RunStatus&)>> run_map = {
        {"channel_switch", CSA_attack::run_chs_attack},
        {"bl0ck", bl0ck_attack::run_bl0ck_attack},
        {"bl0ck_monitor_test", test_monitor_bl0ck::run_attack},
        {"malformed_eapol1", eapol_logoff::run_attack},
        {"cookie_guzzler", cookie_guzzler::run_attack}
    };

    map<string, function<void(const RunStatus&)>> stats_map = {
        {"channel_switch", CSA_attack::stats_chs_attack},
        {"bl0ck", bl0ck_attack::stats_bl0ck_attack},
        {"bl0ck_monitor_test", test_monitor_bl0ck::stats_attack},
        {"malformed_eapol1", eapol_logoff::stats}
    };
}