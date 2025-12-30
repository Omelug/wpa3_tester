#include "attacks/attacks.h"
#include "attacks/channel_switch/channel_switch.h"

std::map<std::string, std::function<void(RunStatus&)>> attack_setup = {
    {"channel_switch", setup_chs_attack},
};

std::map<std::string, std::function<void(RunStatus&)>> attack_run = {
    {"channel_switch", run_chs_attack},
};
