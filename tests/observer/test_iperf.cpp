#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <string>

#include "observer/iperf_wrapper.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester::observer;

namespace{
struct TempLog{
	path p;
	explicit TempLog(const string &content){
		p = temp_directory_path() / ("wpa3_iperf_" +
			to_string(chrono::system_clock::now().time_since_epoch().count()) + ".log");
		ofstream f(p);
		f << content;
	}
	~TempLog(){ remove(p); }
};

// External WB AP server log format: no timestamps, raw iperf3 daemon output.
// 3 consecutive zero intervals (6-7, 7-8, 8-9) -> "unstable" (3 < ZERO_STREAK_THRESHOLD=5)
constexpr string_view EXT_WB_AP_LOG = R"(-----------------------------------------------------------
Server listening on 5201 (test #1)
-----------------------------------------------------------
Accepted connection from 172.16.100.2, port 55079
[  6] local 172.16.100.1 port 5201 connected to 172.16.100.2 port 53885
[  9] local 172.16.100.1 port 5201 connected to 172.16.100.2 port 41387
[ ID][Role] Interval           Transfer     Bitrate         Retr  Cwnd
[  6][RX-S]   0.00-1.00   sec  1.12 MBytes  9.44 Mbits/sec
[  9][TX-S]   0.00-1.00   sec  1.25 MBytes  10.5 Mbits/sec    9   24.0 KBytes
[  6][RX-S]   4.00-5.00   sec  1.25 MBytes  10.5 Mbits/sec
[  9][TX-S]   4.00-5.00   sec  1.12 MBytes  9.44 Mbits/sec   10   46.7 KBytes
[  6][RX-S]   5.00-6.00   sec   256 KBytes  2.10 Mbits/sec
[  9][TX-S]   5.00-6.00   sec   512 KBytes  4.19 Mbits/sec    5   1.41 KBytes
[  6][RX-S]   6.00-7.00   sec  0.00 Bytes  0.00 bits/sec
[  9][TX-S]   6.00-7.00   sec  0.00 Bytes  0.00 bits/sec    1   1.41 KBytes
[  6][RX-S]   7.00-8.00   sec  0.00 Bytes  0.00 bits/sec
[  9][TX-S]   7.00-8.00   sec  0.00 Bytes  0.00 bits/sec    0   1.41 KBytes
[  6][RX-S]   8.00-9.00   sec  0.00 Bytes  0.00 bits/sec
[  9][TX-S]   8.00-9.00   sec  0.00 Bytes  0.00 bits/sec    1   1.41 KBytes
)";

// 5 consecutive zero intervals -> "down"
constexpr string_view FIVE_ZERO_LOG =
	"[  6][RX-S]   0.00-1.00   sec  1.12 MBytes  9.44 Mbits/sec\n"
	"[  6][RX-S]   1.00-2.00   sec  0.00 Bytes  0.00 bits/sec\n"
	"[  6][RX-S]   2.00-3.00   sec  0.00 Bytes  0.00 bits/sec\n"
	"[  6][RX-S]   3.00-4.00   sec  0.00 Bytes  0.00 bits/sec\n"
	"[  6][RX-S]   4.00-5.00   sec  0.00 Bytes  0.00 bits/sec\n"
	"[  6][RX-S]   5.00-6.00   sec  0.00 Bytes  0.00 bits/sec\n";
}

// iperf_log_has_zero_plain

TEST_CASE("iperf_log_has_zero_plain - 3 consecutive zeros -> unstable"){
	TempLog tmp{string(EXT_WB_AP_LOG)};
	const auto r = iperf_log_has_zero_plain(tmp.p);
	CHECK_EQ(r.value(), "unstable");
}

TEST_CASE("iperf_log_has_zero_plain - no zero intervals -> empty"){
	TempLog tmp(
		"[  6][RX-S]   0.00-1.00   sec  1.12 MBytes  9.44 Mbits/sec\n"
		"[  9][TX-S]   0.00-1.00   sec  1.25 MBytes  10.5 Mbits/sec    9   24.0 KBytes\n"
	);
	CHECK(iperf_log_has_zero_plain(tmp.p).empty());
}

TEST_CASE("iperf_log_has_zero_plain - stops at summary separator"){
	// zeros only appear after "- - - -" -> should not be detected
	TempLog tmp(
		"[  6][RX-S]   0.00-1.00   sec  1.12 MBytes  9.44 Mbits/sec\n"
		"- - - - - - - - - - - - - - - - - - -\n"
		"[  6][RX-S]   0.00-10.00  sec  0.00 Bytes  0.00 bits/sec    sender\n"
	);
	CHECK(iperf_log_has_zero_plain(tmp.p).empty());
}

TEST_CASE("iperf_log_has_zero_plain - missing file -> empty"){
	CHECK(iperf_log_has_zero_plain("/tmp/nonexistent_wpa3_iperf_test.log").empty());
}

TEST_CASE("iperf_log_has_zero_plain - 5 consecutive zeros -> down"){
	TempLog tmp{string(FIVE_ZERO_LOG)};
	CHECK_EQ(iperf_log_has_zero_plain(tmp.p).value(), "down");
}

TEST_CASE("iperf_log_has_zero_plain - bidir: only RX zero, TX non-zero -> unstable"){
	// TX-C non-zero comes first; RX-C zero same interval. Bug: old dedup skipped RX.
	TempLog tmp(
		"[  5][TX-C]   2.00-3.00   sec   512 KBytes  4.19 Mbits/sec\n"
		"[  7][RX-C]   2.00-3.00   sec  0.00 Bytes  0.00 bits/sec\n"
	);
	CHECK_EQ(iperf_log_has_zero_plain(tmp.p).value(), "unstable");
}

// ------------Real data tests (files copied from an actual test run)

TEST_CASE("iperf_log_has_zero_plain - real client log (1 zero interval) -> unstable"){
	const path p = "iperf3_real/client_iperf3_gen.log";
	if(!exists(p)){ MESSAGE("Skipping: real data not present at " << p.string()); return; }
	CHECK_EQ(iperf_log_has_zero_plain(p).value(), "unstable");
}

TEST_CASE("iperf_log_has_zero_plain - real AP server log (ctime timestamps, 1 zero interval) -> unstable"){
	const path p = "iperf3_real/ap_iperf3_server.log";
	if(!exists(p)){ MESSAGE("Skipping: real data not present at " << p.string()); return; }
	CHECK_EQ(iperf_log_has_zero_plain(p).value(), "unstable");
}
