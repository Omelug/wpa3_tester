#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::observer{
    void start_thark(RunStatus &run_status, const std::string &node_name);
    std::string tshark_graph(const RunStatus &run_status, const std::string &node_name);
}
