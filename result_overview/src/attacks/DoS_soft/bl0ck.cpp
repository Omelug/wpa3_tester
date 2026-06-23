#include <array>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>
#include "html_guard.h"
#include "suite/suite_helper.h"
#include "suite/DoS_soft/bl0ck/bl0ck_test_suites.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using suite::bl0ck_test_suites::Bl0ckTestEntry;

using TaggedEntry = pair<string, Bl0ckTestEntry>;

static vector<TaggedEntry> collect_results(const path &data_dir) {
    const path bl0ck_base = data_dir / "wpa3_suites" / "DoS_soft" / "bl0ck";
    const array<string, 3> suite_fillers = {"BA_filler", "BAR_filler", "BARS_filler"};

    vector<TaggedEntry> results;

    for (const auto &filler : suite_fillers) {
        for (const auto &src_dir : suite::helper::get_suite_test_folders(bl0ck_base / "suite" / filler)) {
            for (const auto &entry : directory_iterator(src_dir)) {
                if (!entry.is_directory()) continue;
                results.emplace_back("suite", Bl0ckTestEntry::parse(entry.path()));
            }
        }
    }

    for (const auto &src_dir : suite::helper::get_suite_test_folders(bl0ck_base / "Dlink" / "bl0ck_Dlink_suite")) {
        for (const auto &entry : directory_iterator(src_dir)) {
            if (!entry.is_directory()) continue;
            results.emplace_back("Dlink", Bl0ckTestEntry::parse(entry.path()));
        }
    }

    return results;
}

void generate_bl0ck(const path &output_dir, const path &data_dir) {
    const auto results = collect_results(data_dir);

    const path page_dir = output_dir / "attacks" / "dos_soft" / "bl0ck";
    create_public_dirs(page_dir);

	HtmlGuard f(page_dir);
	if(!f) return;

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

    auto emit_table = [&](const string &title, const string &table_id, const string &variant_filter) {
        vector<const Bl0ckTestEntry*> rows;
        for (const auto &[tag, e] : results)
            if (tag == variant_filter) rows.push_back(&e);
        if (rows.empty()) return;

        f << "    <div class=\"card\" style=\"overflow-x: auto;\">\n"
          << "        <h2>" << title << "</h2>\n"
          << "        <table id=\"" << table_id << "\" class=\"aggregate\">\n"
          << "            <thead><tr>\n"
          << "                <th>AP MAC (source)</th>\n"
          << "                <th>Client MAC (source)</th>\n"
          << "                <th>Attacker MAC (driver)</th>\n"
          << "                <th>Variant</th>\n"
          << "                <th>Disconnected?</th>\n"
          << "            </tr></thead>\n"
          << "            <tbody>\n";
        for (const auto *e : rows) {
            f << "                <tr>\n";
            f << "                    <td>" << device(e->ap_mac, page_dir)       << " (" << e->ap_source       << ")</td>\n";
            f << "                    <td>" << device(e->client_mac, page_dir)   << " (" << e->client_source   << ")</td>\n";
            f << "                    <td>" << device(e->attacker_mac, page_dir) << " (" << e->attacker_driver << ")</td>\n";
            f << "                    <td>" << e->attack_variant << "</td>\n";
            f << "                    <td>" << (e->disconnect_count > 0) << "</td>\n";
            f << "                </tr>\n";
        }
        f << "            </tbody>\n        </table>\n    </div>\n";
    };

    if (results.empty()) {
        f << "    <div class=\"card\"><p>No test results found.</p></div>\n";
    } else {
        emit_table("Test Results", "resultsTable", "suite");
        emit_table("Dlink", "resultsTableDlink", "Dlink");
    }

    f << "</body>\n</html>\n";
}

}
