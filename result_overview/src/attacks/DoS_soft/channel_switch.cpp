#include "attacks/DoS_soft/channel_switch.h"
#include <filesystem>
#include <fstream>
#include <string>
#include "suite/DoS_soft/channel_switch/channel_switch_versions.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using suite::channel_switch_filler::CsaTestEntry;
using suite::channel_switch_filler::parse_test_folder;

static vector<CsaTestEntry> collect_results(const path &data_dir) {
    vector<CsaTestEntry> results;
    const path suites_dir = data_dir / "wpa3_suites";
    if (!exists(suites_dir)) return results;

    error_code ec;
    for (const auto &suite : directory_iterator(suites_dir, ec)) {
        if (!suite.is_directory()) continue;
        const path last_run = suite.path() / "last_run";
        if (!exists(last_run)) continue;

        for (const auto &ts_entry : directory_iterator(last_run, ec)) {
            if (!ts_entry.is_directory()) continue;
            if (ts_entry.path().filename().string().find("channel_switch") == string::npos) continue;

            const path inner = ts_entry.path() / "last_run";
            if (!exists(inner)) continue;

            for (const auto &run : directory_iterator(inner, ec)) {
                if (run.is_directory())
                    results.push_back(parse_test_folder(run.path()));
            }
        }
    }
    return results;
}

void generate_channel_switch(const path &output_dir, const path &data_dir) {
    const auto results = collect_results(data_dir);

    const path page_dir = output_dir / "attacks" / "dos_soft" / "channel_switch";
    create_public_dirs(page_dir);
    const path img_dir = page_dir / "img";

    ofstream f(page_dir / "index.html");
    f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSA DoS Attack — Results</title>
    <link rel="stylesheet" href="../../../style.css">
</head>
<body>
    <h1>Channel Switch Announcement (CSA) DoS</h1>

    <div class="card">
        <h2>Attack Description</h2>
        <p>The attacker sends forged CSA beacons causing a connected client to switch
           Wi-Fi channels, disconnecting it from the legitimate AP.</p>
        <img src="../../../images/CSA.svg" alt="CSA attack diagram" style="max-width:100%; margin-top:12px;">
    </div>
)html";

    if (results.empty()) {
        f << "    <div class=\"card\"><p>No test results found.</p></div>\n";
    } else {
        f << R"html(    <div class="card">
        <h2>Test Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Test</th>
                    <th>hostapd</th>
                    <th>wpa_supplicant</th>
                    <th>New ch.</th>
                    <th>Time (s)</th>
                    <th>Graphs</th>
                </tr>
            </thead>
            <tbody>
)html";
        for (const auto &e : results) {
            const string ci = e.name + "_client.png";
            const string ai = e.name + "_ap.png";
            copy_f(e.client_graph, img_dir/ ci);
            copy_f(e.ap_graph,    img_dir /ai);

            f << "                <tr>\n";
            f << "                    <td>" << e.name << "</td>\n";
            f << "                    <td>" << (e.hostapd_version.empty()    ? "?" : e.hostapd_version)    << "</td>\n";
            f << "                    <td>" << (e.supplicant_version.empty() ? "?" : e.supplicant_version) << "</td>\n";
            f << "                    <td>" << (e.new_channel.empty()        ? "?" : e.new_channel)        << "</td>\n";
            f << "                    <td>" << (e.attack_time.empty()        ? "?" : e.attack_time)        << "</td>\n";
            f << "                    <td>";
            if (exists(img_dir / ci)) f << "<a href=\"img/" << ci << "\">STA</a> ";
            if (exists(img_dir / ai)) f << "<a href=\"img/" << ai << "\">AP</a>";
            f << "</td>\n                </tr>\n";
        }
        f << "            </tbody>\n        </table>\n    </div>\n";
    }

    f << "</body>\n</html>\n";
    f.close();
    set_public_perms(page_dir / "index.html");
}

}
