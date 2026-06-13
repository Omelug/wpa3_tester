#include "attacks/DoS_soft/channel_switch.h"
#include <filesystem>
#include <fstream>
#include <string>
#include "suite/DoS_soft/channel_switch/channel_switch_rogueAP.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using suite::channel_switch_rogueAP::CsaTestEntry;

static vector<CsaTestEntry> collect_results(const path &data_dir) {
    vector<CsaTestEntry> results;
    const path suite_dir = data_dir / "wpa3_suites" / "CSA_rogueAP_internal_filler";
    for (const auto &test_path : suite::helper::get_suite_test_folders(suite_dir)) {
        auto e = suite::channel_switch_rogueAP::parse_test_folder(test_path);
        if (!e.passed.has_value()) continue;
        results.push_back(std::move(e));
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
    <script src="../../../table_aggregate.js"></script>
</head>
<body>
    <a href="../../../index.html" class="back-link">← Overview</a>
    <h1>Channel Switch Announcement (CSA) DoS</h1>

    <div class="card">
		<p><b>prerequisites:</b> client connected to legit access_point </p>
        <p>The attacker sends CSA beacons causing a connected client to switch
           Wi-Fi channels, disconnecting it from the legitimate AP.
		   Optionally can attacker create rogue AP on new channel with WPA2 to downgrade and het WPA2 hash </p>
		<p><b>variants:</b> optionally attack can have rogue AP to check downgrade and WPA2 password<p>
		<p><b>success:</b> client disconnected from access_point, in second variant try to connect to rogue AP</p>


<img src="../../../images/CSA.svg" alt="CSA attack diagram" style="max-width:60%; margin-top:12px; display:block; margin-left:auto; margin-right:auto;">
    </div>
)html";

    if (results.empty()) {
        f << "    <div class=\"card\"><p>No test results found.</p></div>\n";
    } else {
        f << R"html(    <div class="card" style="overflow-x: auto;">
        <h2>Test Results</h2>
        <table id="resultsTable">
            <thead>
                <tr>
                    <th>Test</th>
                    <th>AP MAC (source)</th>
                    <th>Client MAC (source)</th>
                    <th>Attacker MAC (driver)</th>
                    <th>Disconnected?</th>
                    <th>Rogue AP?</th>
                    <th>AP OCV / Client OCV</th>
                    <!-- <th>Graphs</th> -->
                </tr>
            </thead>
            <tbody>
)html";
        auto opt_bool = [](const optional<bool> &v) -> string {
            if (!v.has_value()) return "N/A";
            return v.value() ? "yes" : "no";
        };
        for (const auto &e : results) {
            //const string ci = e.name + "_client.png";
            //const string ai = e.name + "_ap.png";
            //copy_f(e.client_graph, img_dir / ci);
            //copy_f(e.ap_graph,    img_dir / ai);

            f << "                <tr>\n";
            f << "                    <td>" << e.name << "</td>\n";
            f << "                    <td>" << e.ap_mac     << " (" << e.ap_source     << ")</td>\n";
            f << "                    <td>" << e.client_mac << " (" << e.client_source << ")</td>\n";
            f << "                    <td>" << e.attacker_mac << " (" << e.attacker_driver << ")</td>\n";
            f << "                    <td>" << opt_bool(e.disconnected) << "</td>\n";
            f << "                    <td>" << opt_bool(e.rogue_ap)     << "</td>\n";
            f << "                    <td>" << opt_bool(e.ap_ocv) << " / " << opt_bool(e.client_ocv) << "</td>\n";
            //f << "                    <td>";
            //if (exists(img_dir / ci)) f << "<a href=\"img/" << ci << "\">STA</a> ";
            //if (exists(img_dir / ai)) f << "<a href=\"img/" << ai << "\">AP</a>";
            //f << "</td>"
            f << "\n                </tr>\n";
        }
        f << "            </tbody>\n        </table>\n    </div>\n";
    }

    f << "</body>\n</html>\n";
    f.close();
    set_public_perms(page_dir / "index.html");
}

}
