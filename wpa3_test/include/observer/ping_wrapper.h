#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::observer::ping {
void start_ping(RunStatus &rs, const std::string &actor_name,
                const std::string &src_name, const std::string &dst_name);
}
