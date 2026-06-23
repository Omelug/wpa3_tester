#include "attacks/DoS_soft/malformed_eapol1.h"
#include <filesystem>
#include <vector>
#include "html_guard.h"
#include "suite/suite_helper.h"
#include "suite/DoS_soft/malformed_eapol1/malformed_eapol1_suite.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using suite::malformed_eapol1_filler::MalformedEapol1TestEntry;

static vector<MalformedEapol1TestEntry> collect_results(const path &data_dir) {
    const path suite_dir = data_dir / "wpa3_suites" / "DoS_soft" / "malformed_eapol1" / "malformed_eapol1_basic_suite";

    vector<MalformedEapol1TestEntry> results;
    for (const auto &test_path : suite::helper::get_suite_test_folders(suite_dir))
        results.push_back(MalformedEapol1TestEntry::parse(test_path / test_path.filename().string()));
    return results;
}

void generate_malformed_eapol1(const path &output_dir, const path &data_dir) {
    const auto results = collect_results(data_dir);

    const path page_dir = output_dir / "attacks" / "dos_soft" / "malformed_eapol1";
    create_public_dirs(page_dir);

    HtmlGuard f(page_dir);
    if (!f) return;

    f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malformed EAPOL-1 DoS — Results</title>
    <link rel="stylesheet" href="../../../style.css">
    <script src="../../../table_aggregate.js"></script>
</head>
<body>
    <a href="../../../index.html" class="back-link">← Overview</a>
    <h1>Malformed EAPOL Key Frame DoS</h1>

    <div class="card">
        <p><b>prerequisites:</b> client attempting WPA3 handshake with access point</p>
        <p>The attacker injects a malformed EAPOL Key frame (invalid tag length) during
           the 4-way handshake, causing the client to disconnect.</p>
        <p><b>success:</b> client disconnected from access point</p>
    </div>

)html";

    if (results.empty()) {
        f << "    <div class=\"card\"><p>No test results found.</p></div>\n";
    } else {
        f << "    <div class=\"card\" style=\"overflow-x: auto;\">\n"
          << "        <h2>Test Results</h2>\n"
          << "        <table id=\"resultsTable\" class=\"aggregate\">\n"
          << "            <thead><tr>\n"
          << "                <th>Test</th>\n"
          << "                <th>AP Driver</th>\n"
          << "                <th>Client Driver</th>\n"
          << "                <th>Client wpa_supplicant version</th>\n"
          << "                <th>Attacker Driver</th>\n"
          << "                <th>Disconnected?</th>\n"
          << "                <th>Rogue AP?</th>\n"
          << "            </tr></thead>\n"
          << "            <tbody>\n";
        for (const auto &e : results) {
            f << "                <tr>\n";
            f << "                    <td>" << e.test_name     << "</td>\n";
            f << "                    <td>" << e.ap_driver     << "</td>\n";
            f << "                    <td>" << e.client_driver << "</td>\n";
            f << "                    <td>" << e.client_version << "</td>\n";
            f << "                    <td>" << e.attacker_driver << "</td>\n";
            f << "                    <td>" << (e.disconnect_count > 0) << " (" << e.disconnect_count << ")</td>\n";
            f << "                    <td>" << e.rogue_ap_connected << "</td>\n";
            f << "                </tr>\n";
        }
        f << "            </tbody>\n        </table>\n    </div>\n";
    }

    f << "</body>\n</html>\n";
}

}
