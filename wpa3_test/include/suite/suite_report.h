#pragma once
#include <functional>
#include <map>
#include <string>

#include "config/RunStatus.h"

namespace wpa3_tester::suite{
    extern std::map<std::string, std::function<void(const RunStatus&)>> suite_report_map;
}
