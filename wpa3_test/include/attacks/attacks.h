#pragma once
#include <map>
#include <string>
#include <functional>
#include "config/RunStatus.h"

namespace wpa3_tester{
    /* map of attacker_module->attack setup function*/
    extern std::map<std::string , std::function<void(RunStatus&)>> attack_setup;
    /* map of attacker_module->attack run function*/
    extern std::map<std::string, std::function<void(RunStatus&)>> attack_run;
    /* map of attacker_module->stats run function*/
    extern std::map<std::string, std::function<void(RunStatus&)>> attack_stats;
}