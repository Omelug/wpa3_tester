#pragma once
#include "config/RunStatus.h"
#include "logger/log.h"

namespace wpa3_tester::observer{
    void start_tcpdump(RunStatus &run_status, const std::string &node_name, const std::string& filter);
}
