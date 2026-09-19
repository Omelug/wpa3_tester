#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include "config/RunStatus.h"

namespace wpa3_tester::observer::dmesg {
// kernel-wide -> not netns-specific
// firmware load errors, kernel warnings, BUG traces
void start_dmesg(RunStatus &rs, const std::string &observer_name, const std::string &level = "",
		const std::string &actor_name = "");

std::vector<std::string> grep_log(const std::filesystem::path &log_file, const std::string &pattern);
inline std::vector<std::string> grep_log(const RunStatus &rs, const std::string &pattern) {
	return grep_log(rs.run_folder() / "observer" / "dmesg" / "dmesg.log", pattern);
}
}
