#pragma once
#include "config/RunStatus.h"
#include "logger/log.h"

namespace wpa3_tester::observer{
    void start_tcpdump_remote(RunStatus &run_status, const std::string &actor_name, const std::string& filter);
    void start_tcpdump(RunStatus &rs, const std::string &actor_name, const std::string& filter);
}
