#include <array>
#include <filesystem>
#include <fstream>
#include <string>
#include "suite/suite_helper.h"
#include "suite/DoS_soft/bl0ck/bl0ck_test_suites.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using suite::bl0ck_test_suites::Bl0ckTestEntry;

static vector<Bl0ckTestEntry> collect_results(const path &data_dir) {
    const path base = data_dir / "wpa3_suites" / "DoS_soft" / "bl0ck";
    const array<string, 3> suites = {"BA_filler", "BAR_filler", "BARS_filler"};

    vector<Bl0ckTestEntry> results;
    for (const auto &suite : suites) {
        for (const auto &test_path : suite::helper::get_suite_test_folders(base / suite)) {
            auto e = Bl0ckTestEntry::parse(test_path);
        	//TODO check nov alid reuslts?
            if (e.disconnected.has_value()) results.push_back(move(e));
        }
    }
    return results;
}

void generate_bl0ck(const path &output_dir, const path &data_dir) {
    const auto results = collect_results(data_dir);

    const path page_dir = output_dir / "attacks" / "dos_soft" / "bl0ck";
    create_public_dirs(page_dir);

    ofstream f(page_dir / "index.html");
    f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bl0ck BA DoS Attack — Results</title>
    <link rel="stylesheet" href="../../../style.css">
    <script src="../../../table_aggregate.js"></script>
</head>
<body>
    <a href="../../../index.html" class="back-link">← Overview</a>
    <h1>Bl0ck — Block ACK (BA) DoS</h1>

    <div class="card">
        <p><b>prerequisites:</b> client connected to access point, QoS data used 802.11ac or 802.11ax</p>
        <p>Bl0ck exploits the Block ACK mechanism by injecting spoofed frames
           that corrupt the receiver's sequence-number state, causing network issues (typycal disconnect)
           subsequent legitimate frames and effectively disconnect.
           Source/python implementation: <a href="https://github.com/efchatz/Bl0ck/tree/main?tab=readme-ov-file" target="_blank">efchatz/Bl0ck</a></p>
        <p><b>variants:</b></p>
        <ul>
            <li><b>BA</b> — attacker sends BA frames spoofing connected STA's MAC with an invalid SSN; the AP stops sending QoS Data frames to all< connected STAs for the duration of the attack. After the attack ends the AP typically recovers.</li>
            <li><b>BAR</b> — attacker sends BAR frames spoofing a connected STA's MAC with an invalid SSN; the AP stops responding with QoS Data to that specific spoofed MAC. The legitimate STA stays connected but cannot receive QoS Data even after the attack ends — requires manual reconnection to recover.</li>
            <li><b>BARS</b> — special case of BAR using a valid SSN instead of an invalid one; the resulting AP behaviour is identical to BAR.</li>
        </ul>
        <p><b>success:</b> client disconnected from access point</p>
    </div>

    <div class="card">
        <h2>Mitigations</h2>
        <p>MFP (Management Frame Protection / 802.11w) protects management frames but
           not bl0ck frames.
		   Protected Block ack Agreement Capable (PBAC) - no widely-deployed mitigation</p>
    </div>
)html"; //FIXME client-AP nesmí být na jedné straně spolu, bl0ck jinak asi nemá dost času -> nějaký WARRNING  ?
    if (results.empty()) {
        f << "    <div class=\"card\"><p>No test results found.</p></div>\n";
    } else {
        f << R"html(    <div class="card" style="overflow-x: auto;">
        <h2>Test Results</h2>
        <table id="resultsTable" class="aggregate">
            <thead>
                <tr>
                    <th>AP MAC (source)</th>
                    <th>Client MAC (source)</th>
                    <th>Attacker MAC (driver)</th>
                    <th>Variant</th>
                    <th>Disconnected?</th>
                </tr>
            </thead>
            <tbody>
)html";
        for (const auto &e : results) {
            f << "                <tr>\n";
            f << "                    <td>" << e.ap_mac       << " (" << e.ap_source       << ")</td>\n";
            f << "                    <td>" << e.client_mac   << " (" << e.client_source   << ")</td>\n";
            f << "                    <td>" << e.attacker_mac << " (" << e.attacker_driver << ")</td>\n";
            f << "                    <td>" << (e.attack_variant.empty() ? "?" : e.attack_variant) << "</td>\n";
            f << "                    <td>" << (e.disconnected.value() ? "yes" : "no")<< "</td>\n";
            f << "                </tr>\n";
        }
        f << "            </tbody>\n        </table>\n    </div>\n";
    }

    f << "</body>\n</html>\n";
    f.close();
    set_public_perms(page_dir / "index.html");
}

}