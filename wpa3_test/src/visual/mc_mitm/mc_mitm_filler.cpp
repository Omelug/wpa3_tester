#include "visual/mc_mitm/mc_mitm_filler.h"

#include <filesystem>
#include <fstream>
#include <string>

#include "default.h"
#include "config/RunSuiteStatus.h"
#include "logger/report.h"
#include "overview/html_guard.h"
#include "overview/html_utils.h"
#include "visual/result_helper.h"
#include "visual/suite_helper.h"

namespace wpa3_tester::visual::mc_mitm_filler {
using namespace std;
using namespace filesystem;

static optional<bool> read_mitm_achieved(const path &test_folder, const string &client_mac) {
    const path state_log = test_folder / "logger" / (client_mac + "_state.log");
    if (!exists(state_log)) return nullopt;
    ifstream f(state_log);
    string line;
    while (getline(f, line)) {
        if (line.find("GotMitm") != string::npos) return true;
    }
    return false;
}

McMitmEntry McMitmEntry::parse(const path &test_folder) {
    McMitmEntry e;
    e.test_name = test_folder.filename().string();

    const auto rs = helper::load_test_rs(test_folder);

    const auto ap = rs->get_actor("ap");
    e.ap_mac = ap->get(SK::mac);

    const auto client = rs->get_actor("client");
    e.client_mac = client->get(SK::mac);

    const auto rogue_client = rs->get_actor("rogue_client");
    e.rogue_client_driver = rogue_client->get(SK::driver_name);

    const auto rogue_ap = rs->get_actor("rogue_ap");
    e.rogue_ap_driver = rogue_ap->get(SK::driver_name);

    e.ssid = rs->config().at("attack_config").at("ssid").get<string>();
    e.mitm_achieved = read_mitm_achieved(test_folder, e.client_mac);

    return e;
}

vector<McMitmEntry> McMitmEntry::collect_results(const path &suite_data_dir) {
    return helper::collect_entries_nested(suite_data_dir, [&suite_data_dir](const path &p) {
        auto e = parse(p);
        e.rel_path = relative(p, suite_data_dir);
        return e;
    });
}

void McMitmEntry::render_table(overview::HtmlGuard &f, const string &title,
    const path &suite_data_dir, const path &) {

    helper::div_card<McMitmEntry>(f, title, suite_data_dir, [&](overview::HtmlGuard &hg,
        const vector<McMitmEntry> &entries) {

        HtmlPathTable t(hg, entries);
        #define COL(name, body) col(name, [&]([[maybe_unused]] const auto &e) { hg << body; })
        t.build([&](auto col) {
            col("AP MAC",               &McMitmEntry::ap_mac);
            col("Client MAC",           &McMitmEntry::client_mac);
            col("rogue_client driver",  &McMitmEntry::rogue_client_driver);
            col("rogue_ap driver",      &McMitmEntry::rogue_ap_driver);
            col("SSID",                 &McMitmEntry::ssid);
            COL("MitM achieved",        e.mitm_achieved);
        })->render();
        #undef COL
    });
}

void McMitmEntry::generate_report(RunSuiteStatus &rss) {
    const auto run_dir = rss.run_folder();
    const auto entries = collect_results(run_dir);

    report::ReportGuard report(run_dir);
    if (!report) return;

    report << "# mc-mitm Test Suite Report\n\n";
    report << "Summary of multi-channel MitM attack tests.\n\n";

    if (entries.empty()) { report << "No test results found.\n"; return; }

    report << "## Test Results\n\n";
    report << "| Test | AP MAC | Client MAC | rogue_client driver | rogue_ap driver | SSID | MitM achieved |\n";
    report << "|------|--------|------------|---------------------|-----------------|------|:--------------|\n";

    for (const auto &e : entries) {
        report << "| " << report::link(e.test_name, e.rel_path / REPORT_NAME) << " | "
               << e.ap_mac << " | "
               << e.client_mac << " | "
               << e.rogue_client_driver << " | "
               << e.rogue_ap_driver << " | "
               << e.ssid << " | "
               << e.mitm_achieved << " |\n";
    }
}

}
