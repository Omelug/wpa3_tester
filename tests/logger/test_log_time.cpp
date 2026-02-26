#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <ctime>
#include <cstdint>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

#include "config/RunStatus.h"
#include "logger/log.h"

using namespace std;
using wpa3_tester::LogTimePoint;

TEST_CASE("log_time_to_epoch_ns - basic UTC+1 timestamp") {
    // 2026-02-20T14:38:08.000000000+0100  →  UTC 13:38:08
    const LogTimePoint tp = wpa3_tester::log_time_to_epoch_ns("2026-02-20T14:38:08.000000000+0100");
    REQUIRE((tp != LogTimePoint{}));

    const time_t t = chrono::system_clock::to_time_t(tp);
    tm utc{};
    gmtime_r(&t, &utc);
    CHECK((utc.tm_year + 1900 == 2026));
    CHECK((utc.tm_mon  + 1   == 2));
    CHECK((utc.tm_mday       == 20));
    CHECK((utc.tm_hour       == 13));   // 14:38 CET → 13:38 UTC
    CHECK((utc.tm_min        == 38));
    CHECK((utc.tm_sec        == 8));

    // no fractional part
    const auto frac = tp.time_since_epoch() % chrono::seconds{1};
    CHECK((frac == chrono::nanoseconds{0}));
}

TEST_CASE("log_time_to_epoch_ns - negative offset UTC-5") {
    // 2026-02-20T08:38:08-0500  →  UTC 13:38:08
    const LogTimePoint tp = wpa3_tester::log_time_to_epoch_ns("2026-02-20T08:38:08.000000000-0500");
    const time_t t = chrono::system_clock::to_time_t(tp);
    tm utc{};
    gmtime_r(&t, &utc);
    CHECK((utc.tm_hour == 13));
}

TEST_CASE("log_time_to_epoch_ns - invalid string returns epoch") {
    CHECK((wpa3_tester::log_time_to_epoch_ns("not-a-timestamp") == LogTimePoint{}));
    CHECK((wpa3_tester::log_time_to_epoch_ns("") == LogTimePoint{}));
}

namespace {
    struct TempLog {
        filesystem::path run_folder;
        string           actor_name;

        TempLog(const string& name, const string& content)
            : run_folder(filesystem::temp_directory_path() / "wpa3_test_log"),
              actor_name(name)
        {
            // mkdtemp needs a writable char buffer
            string tmpl = run_folder.string();
            char buf[PATH_MAX];
            strncpy(buf, tmpl.c_str(), sizeof(buf));
            mkdtemp(buf);
            run_folder = buf;

            const auto log_dir = run_folder / "logger";
            filesystem::create_directories(log_dir);

            ofstream f(log_dir / (name + ".log"));
            f << content;
        }

        ~TempLog() { filesystem::remove_all(run_folder); }
    };

}

TEST_CASE("get_time_logs - finds matching lines") {
    const string log_content =
        "2026-02-20T14:38:08.310201504+0100 [access_point] [stdout] wlan2: AP-ENABLED\n"
        "2026-02-20T14:38:09.000000000+0100 [access_point] [stdout] some other line\n"
        "2026-02-20T14:38:10.500000000+0100 [access_point] [stdout] wlan2: AP-ENABLED\n";

    TempLog tmp("access_point", log_content);
    wpa3_tester::RunStatus rs;
    rs.run_folder = tmp.run_folder;

    const auto times = wpa3_tester::get_time_logs(rs, "access_point", "AP-ENABLED");
    REQUIRE((times.size() == 2));

    INFO("%d",(times[1] - times[0]));
    CHECK_EQ((times[1] - times[0]), chrono::nanoseconds{2189798496ns});
}

TEST_CASE("get_time_logs - no match returns empty") {
    const string log_content =
        "2026-02-20T14:38:08.000000000+0100 [ap] [stdout] some line\n";

    TempLog tmp("ap", log_content);
    wpa3_tester::RunStatus rs;
    rs.run_folder = tmp.run_folder;

    const auto times = wpa3_tester::get_time_logs(rs, "ap", "DOES_NOT_EXIST");
    CHECK(times.empty());
}

TEST_CASE("get_time_logs - missing log file returns empty") {
    wpa3_tester::RunStatus rs;
    rs.run_folder = "/tmp/wpa3_nonexistent_run_folder";

    const auto times = wpa3_tester::get_time_logs(rs, "actor", "pattern");
    CHECK(times.empty());
}

