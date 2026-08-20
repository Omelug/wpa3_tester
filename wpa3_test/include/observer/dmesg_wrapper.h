#pragma once
#include "config/RunStatus.h"
#include <string>

namespace wpa3_tester::observer::dmesg{
// kernel-wide -> not netns-specific
// firmware load errors, kernel warnings, BUG traces.
void start_dmesg(RunStatus &rs, const std::string &actor_name);
}
