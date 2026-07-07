#pragma once
#include "log.h"
#include "config/Actor_Config/actor_keys.h"
#include "config/RunStatus.h"

namespace wpa3_tester{
void log_actor_map(const std::string &name, const ActorCMap &m);

std::vector<LogTimePoint> get_time_logs(const RunStatus &rs, const std::string &process_name,
										const std::string &pattern, bool between_markers = false);
}
