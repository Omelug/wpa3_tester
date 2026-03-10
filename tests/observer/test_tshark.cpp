#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <cstdint>
#include <chrono>
#include <cstdlib>
#include <source_location>
#include "config/RunStatus.h"
#include "observer/tshark_wrapper.h"
#include "logger/log.h"
#include "observer/observers.h"

using namespace std;
using namespace filesystem;

namespace {

struct TsharkGuard {
    TsharkGuard() {
        if (system("tshark --version > /dev/null 2>&1") != 0) {
            log(wpa3_tester::LogLevel::ERROR,
                "[skip] tshark not found, skipping observer tests.");
            exit(0);
        }
    }
};
[[maybe_unused]] const TsharkGuard tshark_guard;

struct TempRunFolder {
    path run_folder;
    string actor;

    TempRunFolder(const string& actor_name, const path& src_pcap)
        : actor(actor_name)
    {
        run_folder = temp_directory_path() / ("wpa3_tshark_" + to_string(chrono::system_clock::now().time_since_epoch().count()));
        const path obs_dir = run_folder / "observer" / "tshark";
        create_directories(obs_dir);

        // copy so the test is self-contained
        copy_file(src_pcap, obs_dir / (actor_name + "_capture.pcap"));
    }

    ~TempRunFolder() { remove_all(run_folder); }
};

}

path this_file = source_location::current().file_name();

TEST_CASE("extract_pcap_to_csv - parses -t ad timestamps from pcapng") {
    const path pcapng = this_file.parent_path() / "test_tshark_minimal.pcapng";
    REQUIRE(exists(pcapng));

    const string actor = "test_actor";
    TempRunFolder tmp(actor, pcapng);

    wpa3_tester::RunStatus rs;
    rs.run_folder = tmp.run_folder.string();

    const path csv_path = wpa3_tester::observer::extract_pcap_to_csv(rs, actor);
    REQUIRE(exists(csv_path));

    const vector<string> expected_lines = {
        "1,2026-02-21T13:12:45.844734691+0100,149",
        "2,2026-02-21T13:12:46.433775945+0100,149"
    };

    ifstream f(csv_path);
    REQUIRE(f.is_open());

    vector<string> actual_lines;
    string line;
    while (getline(f, line)) {
        if (!line.empty())
            actual_lines.push_back(line);
    }

    REQUIRE((actual_lines.size() == expected_lines.size()));
    for (size_t i = 0; i < expected_lines.size(); ++i) {
        CHECK((actual_lines[i] == expected_lines[i]));
    }
}

TEST_CASE("transform_to_relative - converts absolute timestamps to relative") {
    using namespace wpa3_tester;
    using namespace chrono;

    const auto start = system_clock::now();
    const LogTimePoint start_tp = time_point_cast<nanoseconds>(start);

    vector<LogTimePoint> times;
    times.push_back(start_tp + seconds(1));
    times.push_back(start_tp + seconds(2));
    times.push_back(start_tp + milliseconds(3500));

    observer::transform_to_relative(times, start_tp);

    CHECK((duration_cast<seconds>(times[0].time_since_epoch()).count() == 1));
    CHECK((duration_cast<seconds>(times[1].time_since_epoch()).count() == 2));
    CHECK((duration_cast<milliseconds>(times[2].time_since_epoch()).count() == 3500));

    vector<LogTimePoint> empty_times;
    observer::transform_to_relative(empty_times, start_tp);
    CHECK(empty_times.empty());
}

