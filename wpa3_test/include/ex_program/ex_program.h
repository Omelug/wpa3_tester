#pragma once
#include "ex_program/ex_program.h"
#include <map>
#include <string>
#include <functional>

void run_hostapd();

inline std::map<std::string, std::function<void()>> run_process = {
    {"hostapd", run_hostapd}
};
