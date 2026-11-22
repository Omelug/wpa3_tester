#pragma once
#include <functional>
#include <linux/if_packet.h>
#include <optional>
#include <string>
#include "config/RunStatus.h"
namespace wpa3_tester::no_connect {
// inject_fn(frame, fd, addr): return nullopt to keep looping, any value to stop early
using InjectFn = std::function<std::optional<bool>(const frame_raw_t &, int, const sockaddr_ll &)>;
// Shared run loop: opens pcap+socket, starts observers, sleeps, then runs the injection loop.
// Handles RAII for fd and pcap handle. Fixes race: setup_STA is called after sleep_before_sec
// so wpa_supplicant starts scanning only when the injection loop is already running.
void run_attack(RunStatus &rs, const std::string &filter, const std::string &log_msg, InjectFn inject_fn);
// Pre-emptive flood: no pcap trigger - blindly sends a burst every flood_interval_ms for the
// whole attack window. make_frame() is called once after setup_STA so SK::mac is populated.
// Returns total number of frames sent.
using FloodFrameFn = std::function<frame_raw_t()>;
int run_flood_attack(RunStatus &rs, const std::string &log_msg, FloodFrameFn make_frame);
void stats_attack(const RunStatus &rs);
}
