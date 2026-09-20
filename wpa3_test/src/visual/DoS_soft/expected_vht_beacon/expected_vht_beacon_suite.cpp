#include "visual/DoS_soft/expected_vht_beacon/expected_vht_beacon_suite.h"
#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "logger/report.h"
#include "overview/html_guard.h"
#include "overview/html_utils.h"
#include "visual/result_helper.h"
#include "visual/suite_helper.h"
#include <filesystem>

#include "logger/log_util.h"
#include "observer/dmesg_wrapper.h"

namespace wpa3_tester::visual::expected_vht_beacon_suite {
using namespace std;
using namespace filesystem;

ExpVhtTestEntry ExpVhtTestEntry::parse(const path &test_folder) {
    auto e = helper::load_result_default<ExpVhtTestEntry>(test_folder);
    e.name = test_folder.filename().string();

    const auto rs = helper::load_test_rs(test_folder);
    if (!rs) return e;

    const auto &ap = rs->get_actor("ap");
    e.ap_mac    = ap->get(SK::mac);
    e.ap_source = ap->get(SK::source);

    const auto &client = rs->get_actor("client");
    e.client_mac    = client->get(SK::mac);
    e.client_source = client->get(SK::source);

    const auto &att = rs->get_actor("attacker");
    e.attacker_mac    = att->get(SK::mac);
    e.attacker_driver = att->get(SK::driver_name);

    if (const auto rogue = rs->actor("rogue_ap")) {
        e.rogue_ap_mac    = rogue->get(SK::mac);
        e.rogue_ap_driver = rogue->get(SK::driver_name);
    }

	const auto window = helper::get_run_window(*rs);
	e.disconnect_count = static_cast<int>(get_time_logs(*rs, "client", "CTRL-EVENT-DISCONNECTED", window).size());
	e.dmesg_change_mode_disconnect = !observer::dmesg::grep_log(*rs, "appears to change mode").empty();
	e.client_mfp = helper::get_client_mfp(*rs, window);
	e.ap_WPA_support = helper::get_ap_WPA_support(*rs);
	e.client_WPA_support = helper::get_client_WPA_support(*rs, window);
	const TimeWindow window_START{ LogTimePoint{}, get_tag_time(rs->combined_log(), START_tag) };
	e.conn_WPA_version = helper::get_conn_WPA_version(*rs, window_START);

	e.ap_disconnected = helper::get_ap_disconnected(*rs, client->get(SK::mac), window);

    return e;
}

void ExpVhtTestEntry::render_table(overview::HtmlGuard &f, const string &title,
    const path &suite_data_dir, const path &page_dir, const string &t_name) {

    helper::div_card<ExpVhtTestEntry>(f, title, suite_data_dir, [&](overview::HtmlGuard &hg,
        const vector<ExpVhtTestEntry> &entries) {

        HtmlPathTable t(hg, entries, t_name);
        #define COL(name, body) col(name, [&]([[maybe_unused]] const auto &e) { hg << body; })

        t.build([&](auto col) {
            COL("Test",                 e.name);
            COL("AP MAC (source)",      overview::device(e.ap_mac, page_dir) << " (" << e.ap_source << ")");
            COL("Client MAC (source)",  overview::device(e.client_mac, page_dir) << " (" << e.client_source << ")");
            COL("Attacker (driver)",    overview::device(e.attacker_mac, page_dir) << " (" << e.attacker_driver << ")");
            COL("Rogue AP (driver)", overview::device(e.rogue_ap_mac, page_dir) << " (" << e.rogue_ap_driver << ")");
        	COL("Rogue WPA2 AP?\n(cracked)", e.rogue_ap_connected << " (" << e.cracked << ")");
            col("Disconnects",          &ExpVhtTestEntry::disconnect_count);
            col("AP disconnected",      &ExpVhtTestEntry::ap_disconnected);
            col("dmesg change mode",    &ExpVhtTestEntry::dmesg_change_mode_disconnect);
        })->render({"Test"});
        #undef COL
    });
}

void ExpVhtTestEntry::generate_report(RunSuiteStatus &rss) {
    const auto run_dir = rss.run_folder();
    const auto entries = helper::get_results_default<ExpVhtTestEntry>(run_dir);
    report::ReportGuard report(run_dir);
    if (!report) return;

    report << "# Expected VHT Beacon DoS Test Report\n\n";
    if (entries.empty()) {
        report << "No test results found.\n";
        return;
    }

    report << "| Test | AP | Client | Attacker (driver) | Disconnects | dmesg change mode |\n";
    report << "|------|----|--------|-------------------|-------------|-------------------|\n";
    for (const auto &e : entries) {
        report << "| " << e.name << " | "
               << e.ap_mac << " (" << e.ap_source << ") | "
               << e.client_mac << " | "
               << e.attacker_mac << " (" << e.attacker_driver << ") | "
               << e.disconnect_count << " | "
               << (e.dmesg_change_mode_disconnect ? "yes" : "no") << " |\n";
    }
}

}
