#include "attacks/downgrade/owe_trans.h"
#include <array>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>
#include "html_guard.h"
#include "logger/log.h"
#include "suite/downgrade/owe_trans_filler.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using suite::owe_trans_filler::OweTransTestEntry;

struct TaggedEntry {
    string tag;
    path folder;
    OweTransTestEntry e;
};

static vector<TaggedEntry> collect_results(const path &data_dir) {
    const path suite_dir = data_dir / "wpa3_suites" / "downgrade" / "owe_trans" / "owe_trans_filler";

    vector<TaggedEntry> results;
    for (const auto &src_dir : suite::helper::get_suite_test_folders(suite_dir)) {
        const string tag = src_dir.filename().string();
        for (const auto &entry : directory_iterator(src_dir)) {
            if (!entry.is_directory()) continue;
        	if(!exists(path(entry)/DONE_FILE)){
        		log(LogLevel::ERROR, "{} not found", DONE_FILE);
        		continue;
        	}
            results.push_back({tag, entry.path(), OweTransTestEntry::parse(entry.path())});
        }
    }
    return results;
}

void generate_owe_trans(const path &output_dir, const path &data_dir) {
    const auto results = collect_results(data_dir);

    const path page_dir = output_dir / "attacks" / "downgrade" / "owe_trans";
    create_public_dirs(page_dir);

    HtmlGuard f(page_dir);
    if (!f) return;

    f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWE Transition Probe Leak — Results</title>
    <link rel="stylesheet" href="../../../style.css">
    <script src="../../../table_aggregate.js"></script>
</head>
<body>
    <a href="../../../index.html" class="back-link">← Overview</a>
    <h1>OWE Transition — Probe Request Leak</h1>

    <div class="card">
        <p><b>Prerequisites:</b> client connected to an OWE transition-mode AP (open + OWE BSS pair).</p>
        <p>After the OWE AP is stopped, a client with autoconnect will emit probe requests to rediscover
           the network. Broadcast probes (empty SSID) reveal that the device is scanning; directed SSID probes
           additionally reveal the preferred network name.</p>
        <p><b>Success:</b> at least one SSID probe request detected after AP shutdown.</p>
    </div>

    <div class="card">
        <h2>Mitigations</h2>
        <ul>
            <li>MAC address randomisation/li>
        </ul>
    </div>
)html";

    auto emit_table = [&](const string &title, const string &table_id, const string &tag_filter) {
        vector<const TaggedEntry*> rows;
        for (const auto &te : results)
            if (te.tag == tag_filter) rows.push_back(&te);
        if (rows.empty()) return;

        f << "    <div class=\"card\" style=\"overflow-x: auto;\">\n"
          << "        <h2>" << title << "</h2>\n"
          << "        <table id=\"" << table_id << "\" class=\"aggregate\">\n"
          << "            <thead><tr>\n"
          << "                <th>Test</th>\n"
          << "                <th>AP Driver</th>\n"
          << "                <th>Client Driver</th>\n"
          << "                <th>Attacker Driver</th>\n"
          << "                <th>BC probes</th>\n"
          << "                <th>SSID probes</th>\n"
          << "                <th>Disconnected</th>\n"
          << "                <th>Vulnerable</th>\n"
          << "            </tr></thead>\n"
          << "            <tbody>\n";
        for (const auto *te : rows) {
            const auto &e = te->e;
            const bool vuln = e.ssid_probe_count > 0;
            f << "                <tr>\n"
              << "                    <td>" << test_name_cell(te->folder, e.test_name, page_dir) << "</td>\n"
              << "                    <td>" << e.ap_driver << "</td>\n"
              << "                    <td>" << e.client_driver << "</td>\n"
              << "                    <td>" << e.attacker_driver << "</td>\n"
              << "                    <td>" << e.broadcast_probe_count << "</td>\n"
              << "                    <td>" << e.ssid_probe_count << "</td>\n"
              << "                    <td>" << e.disconnected << "</td>\n"
              << "                    <td>" << vuln << "</td>\n"
              << "                </tr>\n";
        }
        f << "            </tbody>\n        </table>\n    </div>\n";
    };

    if (results.empty()) {
        f << "    <div class=\"card\"><p>No test results found.</p></div>\n";
    } else {
        emit_table("All Actors", "tAllActors", "all_actors");
    }

    f << "</body>\n</html>\n";
}

}
