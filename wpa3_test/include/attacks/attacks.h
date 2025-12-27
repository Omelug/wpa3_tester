#pragma once
#include <map>
#include <string>
#include <functional>
#include "config/RunStatus.h"

extern std::map<std::string, std::function<void(RunStatus&)>> attack_setup;
extern std::map<std::string, std::function<void(RunStatus&)>> attack_run;
