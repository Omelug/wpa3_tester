#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::observer{
    void start_thark(RunStatus &run_status, const std::string &node_name);
    void tshark_graph(const RunStatus &run_status, const std::string &node_name);
}
