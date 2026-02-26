#include "attacks/attacks.h"
#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "attacks/DoS_soft//bl0ck/bl0ck.h"

namespace wpa3_tester::attack_module_maps{
    using namespace std;

    map<string, function<void(RunStatus&)>> setup_map = {
        {"channel_switch", CSA_attack::setup_chs_attack},
        {"bl0ck", CSA_attack::setup_chs_attack}
    };

    map<string, function<void(RunStatus&)>> run_map = {
        {"channel_switch", CSA_attack::run_chs_attack},
        {"bl0ck", bl0ck_attack::run_bl0ck_attack}
    };

    map<string, function<void(const RunStatus&)>> stats_map = {
        {"channel_switch", CSA_attack::stats_chs_attack},
        {"bl0ck", bl0ck_attack::stats_bl0ck_attack}
    };
}