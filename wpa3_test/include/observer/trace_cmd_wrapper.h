#pragma once
#include "config/RunStatus.h"
#include "observer/graph/graph_elements.h"
#include "overview/described.h"
#include <map>
#include <string>
#include <vector>
namespace wpa3_tester::observer::trace_cmd{

// ieee80211_ampdu_mlme_action from <net/mac80211.h>
// https://github.com/torvalds/linux/blob/master/include/net/mac80211.h
enum class AmpduAction : int {
	RX_START            = 0,
	RX_STOP             = 1,
	TX_OPERATIONAL      = 2,
	TX_STOP_CONT        = 3,
	TX_STOP_FLUSH       = 4,
	TX_STOP_FLUSH_CONT  = 5,
	TX_START            = 6,
	TX_START_DELAY      = 7,
	UNKNOWN             = -1,
};

// Y-axis labels for GraphStairs<AmpduAction>
const std::vector<std::pair<AmpduAction, std::string>>& ampdu_action_labels();

// kernel-wide ftrace tracepoints
// not netns-specific.
// requires CONFIG_ATH_TRACEPOINTS, CONFIG_MAC80211_DEBUG_MENU during kernel compilation
// output: binary .dat (kept) + human-readable .txt
// kprobes: each string is passed as --kprobe "[NAME=]FUNC[+OFFSET] [ARGS]"
//          defines and enables the kprobe in one step (no separate -e needed)
// Records a wall/monotonic clock reference for timestamp conversion in get_bl0ck_logs.
void start_trace_cmd(RunStatus &rs, const std::string &actor_name,
                     const std::vector<std::string> &events,
                     const std::vector<std::string> &kprobes = {});

// parse mac80211:drv_ampdu_action events from the trace_cmd text log of actor_name
// timestamps are converted to system_clock using the clock reference written by start_trace_cmd
// returns empty if trace log/clock reference is missing
std::map<LogTimePoint, AmpduAction> get_bl0ck_logs(const RunStatus &rs,
                                                    const std::string &actor_name);

// check whether a QoS/AMPDU Block-ACK session was established (ADDBA)
// actor whose trace file exists
// actors that are WB (remote) or have no trace file are silently skipped
// mt76x2u probably don't  support control_monitor
described_bool addba_seen(const RunStatus &rs);
}
