#pragma once
#include <filesystem>
#include <string>
#include "config/RunStatus.h"

namespace wpa3_tester::observer{
    void start_resource_monitoring(RunStatus &rs, const std::string &actor_name, int interval_sec);
    void start_resource_monitoring_remote(RunStatus &rs, const std::string &actor_name, int interval_sec);
}
