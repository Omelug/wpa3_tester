#include "attacks/attacks.h"

std::map<std::string, std::function<void(const RunStatus&)>> attack_setup = {
    {"channel_switch", setup_chs_attack},
};

std::map<std::string, std::function<void(const RunStatus&)>> attack_run = {
    {"channel_switch", run_chs_attack},
};

