#pragma once
#include <filesystem>
#include <string>
#include "config/RunStatus.h"

namespace wpa3_tester::observer::state_log_graph {

inline constexpr std::string SUFFIX_state = "_state";

// parse <mac>_state.log in rs.run_folder()/logger/ and write staircase PNG beside it
// call at the END of a test, after state transitions logging have been finished
void create_state_log_graph(const RunStatus &rs, const std::string &mac_str);

// read state_log_path and write PNG to output_png.
void create_state_log_graph(const std::filesystem::path &state_log_path,
                             const std::filesystem::path &output_png);

}
