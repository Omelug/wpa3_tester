#pragma once
#include "log.h"
#include "config/RunStatus.h"
#include "config/Actor_Config/actor_keys.h"

namespace wpa3_tester{
void log_actor_map(const std::string &name, const ActorCMap &m);

std::vector<LogTimePoint> get_time_logs(const RunStatus &rs, const std::string &process_name,
										const std::string &pattern, bool between_markers = false);

// Returns the timestamp of the first log line containing `tag`, or epoch-zero if not found.
LogTimePoint get_tag_time(const std::filesystem::path &log_path, const std::string &tag);
}
