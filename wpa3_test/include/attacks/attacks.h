#pragma once
#include <map>
#include <string>
#include <functional>
#include "channel_switch/channel_switch.h"
std::map<std::string, std::function<void()>> attack_setup = {
    {"channel_switch", setup_attack},
};
