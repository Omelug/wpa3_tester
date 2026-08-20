#pragma once
#include <string>
#include <vector>
#include "config/RunStatus.h"

namespace wpa3_tester::observer::trace_cmd{
// Both functions capture kernel-wide events — NOT netns-specific.
// trace-cmd uses ftrace tracepoints (structured, typed events with timing).
// dmesg captures printk messages (driver errors, firmware failures, crashes).
// They are complementary: trace-cmd shows what happened, dmesg shows what went wrong.

void start_trace_cmd(RunStatus &rs, const std::string &actor_name,
                     const std::vector<std::string> &events);

// Requires CONFIG_ATH_TRACEPOINTS, CONFIG_MAC80211_DEBUG_MENU, etc. in kernel.
// Typical events: "mac80211", "ath9k", "cfg80211", "net"
// Output: binary .dat (kept) + human-readable .txt (converted on stop)

void start_dmesg(RunStatus &rs, const std::string &actor_name);
// Follows new kernel ring buffer messages during the test.
// Catches what trace-cmd misses: firmware load errors, kernel warnings, BUG traces.
}
