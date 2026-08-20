#pragma once
#include "config/RunStatus.h"
#include <string>
#include <vector>

namespace wpa3_tester::observer::trace_cmd{
// kernel-wide ftrace tracepoints
// not netns-specific.
// requires CONFIG_ATH_TRACEPOINTS, CONFIG_MAC80211_DEBUG_MENU, etc.
// output: binary .dat (kept) + human-readable .txt (converted on stop)
// kprobes: each string is passed as --kprobe "[NAME=]FUNC[+OFFSET] [ARGS]"
//          defines and enables the kprobe in one step (no separate -e needed)
void start_trace_cmd(RunStatus &rs, const std::string &actor_name,
                     const std::vector<std::string> &events,
                     const std::vector<std::string> &kprobes = {});
}
