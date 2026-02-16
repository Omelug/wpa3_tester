#pragma once
#include <map>
#include <string>
#include <functional>
#include "config/RunStatus.h"

namespace wpa3_tester::attack_module_maps{
    /* map of attacker_module->attack setup function*/
    extern std::map<std::string , std::function<void(RunStatus&)>> setup_map;
    /* map of attacker_module->attack run function*/
    extern std::map<std::string, std::function<void(RunStatus&)>> run_map;
    /* map of attacker_module->stats run function*/
    extern std::map<std::string, std::function<void(RunStatus&)>> stats_map;
}