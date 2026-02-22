#include "attacks/attacks.h"
#include "attacks/channel_switch/channel_switch.h"
#include "attacks/bl0ck/bl0ck.h"

namespace wpa3_tester::attack_module_maps{
    using namespace std;
    map<string, function<void(RunStatus&)>> setup_map = {
        {"channel_switch", setup_chs_attack},
        {"bl0ck", setup_chs_attack},
    };

    map<string, function<void(RunStatus&)>> run_map = {
        {"channel_switch", run_chs_attack},
        {"bl0ck", run_bl0ck_attack}
    };

    map<string, function<void(RunStatus&)>> stats_map = {
        {"channel_switch", stats_chs_attack},
        {"bl0ck", stats_bl0ck_attack},
    };
}