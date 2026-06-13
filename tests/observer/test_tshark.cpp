#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <chrono>
#include <cstdlib>
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <memory>
#include <source_location>
#include <string>

#include "config/RunStatus.h"
#include "config/Actor_Config/Actor_config.h"
#include "config/Actor_Config/Actor_Config_sim.h"
#include "logger/log.h"
#include "observer/observers.h"
#include "observer/tshark_wrapper.h"
#include "system/utils.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester;
using namespace wpa3_tester::observer::tshark;

namespace{
bool tshark_available(){
    return system("tshark --version > /dev/null 2>&1") == 0;
}

path this_file = source_location::current().file_name();

ActorPtr make_actor(const string &mac){
    auto cfg = ActorPtr(make_shared<Actor_Config_sim>());
    cfg->set(SK::mac, mac);
    return ActorPtr(cfg);
}

struct TempCsv{
    path p;
    explicit TempCsv(const string &content){
        p = temp_directory_path() / ("wpa3_test_csv_" +
            to_string(chrono::system_clock::now().time_since_epoch().count()) + ".csv");
        ofstream f(p);
        f << content;
    }
    ~TempCsv(){ remove(p); }
};
}

// ---- or_filter ----

TEST_CASE("or_filter - empty vector returns empty string"){
    CHECK_EQ(or_filter({}), "");
}

TEST_CASE("or_filter - single element wrapped in parens"){
    CHECK_EQ(or_filter({"ether host aa:bb:cc:dd:ee:ff"}), "(ether host aa:bb:cc:dd:ee:ff)");
}

TEST_CASE("or_filter - multiple elements joined with ' or '"){
    const string result = or_filter({"A", "B", "C"});
    CHECK_EQ(result, "(A or B or C)");
}

// ---- all_actors_mac_filter ----

TEST_CASE("all_actors_mac_filter - single actor no broadcast"){
    RunStatus rs;
    rs.actors["sta"] = make_actor("aa:bb:cc:dd:ee:ff");

    const string f = all_actors_mac_filter(rs, false);
    CHECK_EQ(f, "(wlan host aa:bb:cc:dd:ee:ff)");
}

TEST_CASE("all_actors_mac_filter - single actor with broadcast"){
    RunStatus rs;
    rs.actors["sta"] = make_actor("aa:bb:cc:dd:ee:ff");

    const string f = all_actors_mac_filter(rs, true);
    CHECK_NE(f.find("wlan host aa:bb:cc:dd:ee:ff"), string::npos);
    CHECK_NE(f.find("wlan host ff:ff:ff:ff:ff:ff"), string::npos);
}

TEST_CASE("all_actors_mac_filter - two actors both present"){
    RunStatus rs;
    rs.actors["sta1"] = make_actor("11:22:33:44:55:66");
    rs.actors["sta2"] = make_actor("aa:bb:cc:dd:ee:ff");

    const string f = all_actors_mac_filter(rs, false);
    CHECK_NE(f.find("wlan host 11:22:33:44:55:66"), string::npos);
    CHECK_NE(f.find("wlan host aa:bb:cc:dd:ee:ff"), string::npos);
    CHECK_NE(f.find(" or "), string::npos);
}

TEST_CASE("all_actors_mac_filter - empty actors returns empty string"){
    RunStatus rs;
    CHECK_EQ(all_actors_mac_filter(rs), "");
}

// ---- masked_mac_filter_5 ----

TEST_CASE("masked_mac_filter_5 - single valid MAC produces link[] filter"){
    RunStatus rs;
    rs.actors["sta"] = make_actor("aa:bb:cc:dd:ee:ff");

    const string f = masked_mac_filter_5(rs);
    // First 5 bytes: aa bb cc dd ee → aabbccddee
    CHECK_NE(f.find("0xaabbccdd"), string::npos);
    CHECK_NE(f.find("0xee"), string::npos);
    CHECK_NE(f.find("link[4:4]"), string::npos);
    CHECK_NE(f.find("link[10:4]"), string::npos);
}

TEST_CASE("masked_mac_filter_5 - MAC shorter than 10 hex chars is skipped"){
    RunStatus rs;
    rs.actors["sta"] = make_actor("aa:bb");  // only 4 hex chars after colon removal

    const string f = masked_mac_filter_5(rs);
    CHECK_EQ(f, "");
}

TEST_CASE("masked_mac_filter_5 - two actors joined with or"){
    RunStatus rs;
    rs.actors["sta1"] = make_actor("aa:bb:cc:dd:ee:ff");
    rs.actors["sta2"] = make_actor("11:22:33:44:55:66");

    const string f = masked_mac_filter_5(rs);
    CHECK_NE(f.find("0xaabbccdd"), string::npos);
    CHECK_NE(f.find("0x11223344"), string::npos);
    CHECK_NE(f.find(" or "), string::npos);
}

// ---- times_packet_sizes_from_csv ----

TEST_CASE("times_packet_sizes_from_csv - two valid rows"){
    TempCsv tmp(
        "1,2026-02-21T13:12:45.844734691+0100,149\n"
        "2,2026-02-21T13:12:46.433775945+0100,200\n"
    );

    auto [times, sizes] = times_packet_sizes_from_csv(tmp.p);

    CHECK_EQ(times.size(), 2u);
    CHECK_EQ(sizes.size(), 2u);
    CHECK_EQ(sizes[0], doctest::Approx(149.0));
    CHECK_EQ(sizes[1], doctest::Approx(200.0));
    CHECK_LT(times[0], times[1]);
}

TEST_CASE("times_packet_sizes_from_csv - invalid timestamp rows are skipped"){
    TempCsv tmp(
        "1,INVALID_TIME,100\n"
        "2,2026-02-21T13:12:46.433775945+0100,200\n"
    );

    auto [times, sizes] = times_packet_sizes_from_csv(tmp.p);

    CHECK_EQ(sizes.size(), 1u);
    CHECK_EQ(sizes[0], doctest::Approx(200.0));
}

TEST_CASE("times_packet_sizes_from_csv - empty file returns empty vectors"){
    TempCsv tmp("");

    auto [times, sizes] = times_packet_sizes_from_csv(tmp.p);

    CHECK(times.empty());
    CHECK(sizes.empty());
}

// ---- extract_pcap_to_csv  /  get_pcap_start_time  (require tshark) ----

TEST_CASE("extract_pcap_to_csv - produces csv with frame,time,len columns"){
    if(!tshark_available()){
        MESSAGE("tshark not found, skipping");
        return;
    }

    const path pcapng = this_file.parent_path() / "test_tshark_minimal.pcapng";
    REQUIRE(exists(pcapng));

    const path out_dir = temp_directory_path() / ("wpa3_pcap_" +
        to_string(chrono::system_clock::now().time_since_epoch().count()));
    create_directories(out_dir);

    const string actor = "test_actor";
    copy_f(pcapng, out_dir / (actor + "_capture.pcap"));

    const path csv = extract_pcap_to_csv(actor, out_dir);
    REQUIRE(exists(csv));

    ifstream f(csv);
    string line;
    int count = 0;
    while(getline(f, line)){
        if(line.empty()) continue;
        ++count;
        CHECK_NE(line.find(','), string::npos);
    }
    CHECK_GE(count, 1);

    remove_all(out_dir);
}

TEST_CASE("get_pcap_start_time - returns nonzero time for known pcap"){
    if(!tshark_available()){
        MESSAGE("tshark not found, skipping");
        return;
    }

    const path pcapng = path(this_file).parent_path() / "test_tshark_minimal.pcapng";
    REQUIRE(exists(pcapng));

    const LogTimePoint tp = get_pcap_start_time(pcapng);
    CHECK_NE(tp.time_since_epoch().count(), 0);

    const time_t t = chrono::system_clock::to_time_t(tp);
    tm utc{};
    gmtime_r(&t, &utc);
    CHECK_EQ(utc.tm_year + 1900, 2026);
    CHECK_EQ(utc.tm_mon + 1, 2);
    CHECK_EQ(utc.tm_mday, 21);
}

// ---- transform_to_relative ----

TEST_CASE("transform_to_relative - converts absolute timestamps to relative"){
    using namespace chrono;

    const auto start = system_clock::now();
    const LogTimePoint start_tp = time_point_cast<nanoseconds>(start);

    vector<LogTimePoint> times;
    times.push_back(start_tp + seconds(1));
    times.push_back(start_tp + seconds(2));
    times.push_back(start_tp + milliseconds(3500));

    observer::transform_to_relative(times, start_tp);

    CHECK_EQ(duration_cast<seconds>(times[0].time_since_epoch()).count(), 1);
    CHECK_EQ(duration_cast<seconds>(times[1].time_since_epoch()).count(), 2);
    CHECK_EQ(duration_cast<milliseconds>(times[2].time_since_epoch()).count(), 3500);

    vector<LogTimePoint> empty_times;
    observer::transform_to_relative(empty_times, start_tp);
    CHECK(empty_times.empty());

}
