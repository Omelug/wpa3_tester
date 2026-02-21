#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::observer{
    void start_musezahn(RunStatus& run_status, const std::string &actor_name,  const std::string &src_name, const std::string &dst_name);
}
