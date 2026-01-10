#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester{
    void set_ip(RunStatus& run_status, const std::string &actor_name);
}
