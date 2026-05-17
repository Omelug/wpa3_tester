#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <tins/tins.h>
#include "../manual_test_core/manual_test_wizards.h"
#include "attacks/mc_mitm/MonitorSocket.h"
#include "system/hw_capabilities.h"
#include "system/injection_result.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;
using namespace wpa3_tester::manual_tests;

// Select a second interface (inject or monitor), different from the first.
static string pick_second_iface(const string &first){
    cout << "\nSelect a second interface (for " << (first.empty() ? "capture" : "monitor") << "):\n";
    const auto iface_ptr = get_iface_wizard();
    if(!iface_ptr) throw manual_test_err("No second interface selected.");
    if(*iface_ptr == first) throw manual_test_err("Both interfaces are the same.");
    return *iface_ptr;
}

TEST_CASE("injection_test_two_iface"){
    cli_section("Two-Interface Injection Test");
    cout << "Select INJECT interface:\n";
    auto iface_out_ptr = get_iface_wizard();
    REQUIRE_NE(iface_out_ptr, nullptr);
    const string& iface_out = *iface_out_ptr;

    cout << "\nSelect MONITOR (capture) interface:\n";
    const string iface_in = pick_second_iface(iface_out);

    const Channel channel{get_2_4_channel_wizard(), WifiBand::BAND_2_4};
    cout << "Setting up interfaces on channel " << channel.ch_num << "...\n";
    hw_capabilities::setup_injection_iface(iface_out, channel);
    hw_capabilities::setup_injection_iface(iface_in,  channel);

    // peermac = MAC of the monitor interface (fallback for retrans test if no AP found)
    const auto peermac = hw_capabilities::get_mac_address(iface_in, nullopt);

    MonitorSocket sout(iface_out);
    MonitorSocket sin (iface_in);

    const auto suite = hw_capabilities::run_injection_tests(
        sout, iface_out,
        sin,
        channel,
        peermac,
        /*skip_mf=*/false,
        /*testack=*/true
    );

    const string md = print_injection_result(suite);
    cout << md;

    // Write to file
    string slug = iface_out + "_" + iface_in;
    ranges::replace(slug, '/', '_');
    const filesystem::path out_dir = filesystem::path(PROJECT_ROOT_DIR).parent_path() / "data" / "tests";
    filesystem::create_directories(out_dir);
    const filesystem::path out_path = out_dir / ("two_iface_injection_" + slug + ".md");
    if(ofstream f(out_path); f.is_open()){
        f << "# Two-Interface Injection Test\n\n" << md;
        cout << "Report written to: " << out_path << "\n";
    }
    //CHECK_EQ(suite.overall_flags(), 0);
}
