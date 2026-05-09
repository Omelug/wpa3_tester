#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::observer{
void start_mausezahn(RunStatus &rs, const std::string &actor_name, const std::string &src_name,
					const std::string &dst_name
);
}