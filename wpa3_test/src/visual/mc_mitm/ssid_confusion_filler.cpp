#include "visual/mc_mitm/ssid_confusion_filler.h"

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

namespace wpa3_tester::visual::ssid_confusion_filler {
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

SsidConfusionEntry SsidConfusionEntry::parse(const path &test_folder) {
    SsidConfusionEntry e;
    e.test_name = test_folder.filename().string();

    const auto rs = helper::load_test_rs(test_folder);

    const auto ap = rs->get_actor("ap");
    e.ap_mac = ap->get(SK::mac);
    e.real_ssid = ap["ssid"];

    const auto client = rs->get_actor("client");
    e.client_mac = client->get(SK::mac);

    const auto rogue_client = rs->get_actor("rogue_client");
    e.rogue_client_driver = rogue_client->get(SK::driver_name);

    const auto rogue_ap = rs->get_actor("rogue_ap");
    e.rogue_ap_driver = rogue_ap->get(SK::driver_name);

    const auto &att_cfg = rs->config().at("attack_config");
    e.confused_ssid = att_cfg.value("confused_ssid", e.real_ssid);
    e.strip_rsn = att_cfg.value("strip_rsn", false);

    e.mitm_achieved = read_mitm_achieved(test_folder, e.client_mac);

    return e;
}

vector<SsidConfusionEntry> SsidConfusionEntry::collect_results(const path &suite_data_dir) {
    return helper::collect_entries_nested(suite_data_dir, [&suite_data_dir](const path &p) {
        auto e = parse(p);
        e.rel_path = relative(p, suite_data_dir);
        return e;
    });
}

void SsidConfusionEntry::render_table(overview::HtmlGuard &f, const string &title,
    const path &suite_data_dir, const path &) {

    helper::div_card<SsidConfusionEntry>(f, title, suite_data_dir, [&](overview::HtmlGuard &hg,
        const vector<SsidConfusionEntry> &entries) {

        HtmlPathTable t(hg, entries);
        #define COL(name, body) col(name, [&]([[maybe_unused]] const auto &e) { hg << body; })
        t.build([&](auto col) {
            col("AP MAC",              &SsidConfusionEntry::ap_mac);
            col("Client MAC",          &SsidConfusionEntry::client_mac);
            col("rogue_client driver", &SsidConfusionEntry::rogue_client_driver);
            col("rogue_ap driver",     &SsidConfusionEntry::rogue_ap_driver);
            col("Real SSID",           &SsidConfusionEntry::real_ssid);
            col("Confused SSID",       &SsidConfusionEntry::confused_ssid);
            COL("Strip RSN",           e.strip_rsn);
            COL("MitM achieved",       e.mitm_achieved);
        })->render();
        #undef COL
    });
}

void SsidConfusionEntry::generate_report(RunSuiteStatus &rss) {
    const auto run_dir = rss.run_folder();
    const auto entries = collect_results(run_dir);

    report::ReportGuard report(run_dir);
    if (!report) return;

    report << "# SSID Confusion Attack Test Suite Report\n\n";
    report << "Summary of SSID confusion (CVE-2023-52424) attack tests.\n\n";

    if (entries.empty()) { report << "No test results found.\n"; return; }

    report << "## Test Results\n\n";
    report << "| Test | AP MAC | Client MAC | Real SSID | Confused SSID | Strip RSN | MitM achieved |\n";
    report << "|------|--------|------------|-----------|---------------|-----------|:--------------|\n";

    for (const auto &e : entries) {
        report << "| " << report::link(e.test_name, e.rel_path / REPORT_NAME) << " | "
               << e.ap_mac << " | "
               << e.client_mac << " | "
               << e.real_ssid << " | "
               << e.confused_ssid << " | "
               << (e.strip_rsn ? "yes" : "no") << " | "
               << e.mitm_achieved << " |\n";
    }
}

}
