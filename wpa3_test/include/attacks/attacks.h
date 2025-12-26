#pragma once
#include <map>
#include <string>
#include <functional>
#include "channel_switch/channel_switch.h"
#include "config/RunStatus.h"

extern std::map<std::string, std::function<void(RunStatus&)>> attack_setup;
extern std::map<std::string, std::function<void(RunStatus&)>> attack_run;
