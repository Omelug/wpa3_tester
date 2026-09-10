#include "attacks/DoS_soft/expected_vht_beacon.h"
#include <filesystem>
#include <string>
#include "overview/html_utils.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;

void generate_expected_vht_beacon(const path &output_dir, const path &data_dir) {
    const path page_dir = output_dir / "attacks" / "DoS_soft" / "expected_vht_beacon";
    create_public_dirs(page_dir);

    HtmlGuard f(page_dir);
    if (!f) return;

    f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Expected VHT Beacon DoS - Results</title>
    <link rel="stylesheet" href="../../../style.css">
    <script src="../../../table_aggregate.js"></script>
</head>
<body>
    <a href="../../../index.html" class="back-link"><- Overview</a>
    <h1>Fake Legacy Beacon DoS (expected VHT, found legacy)</h1>

    <div class="card">
        <p><b>prerequisites:</b> client connected to a HT/VHT access point</p>
        <p>
            The attacker captures the real AP beacon
			Filter out  VHT_CAP, VHT_OP, HT_* etc.
            Re-injects the modified beacon using the AP's BSSID
			The mac80211 kernel driver detects that the AP appears to have switched from HT to legacy/VHT to legacy mode and forcibly disconnects the client.
        </p>
        <p>
            On mt76x2u its <b>side-effect</b> of the Bl0ck/BARS attack on mt76x2u
        </p>
        <p><b>success:</b> client receives fake legacy beacon and disconnects from the AP</p>
    </div>

    <div class="card">
        <h2>Mitigations</h2>
        <ul>
            <li><b>Beacon Protection (BIGTK, 802.11ax)</b> — fake beacons without a valid
                BIP-CMAC-256 tag are silently dropped. Not yet widely deployed.</li>
            <li> #TODO source, soplnit
        </ul>
    </div>

)html";

    // TODO: add result table once runs are collected
    // Example pattern when a visual helper exists:
    // auto emit_table = [&](const string &title, const path &suite_data_dir, const string &t_name){
    //     ExpectedVhtTestEntry::render_table(f, title, suite_data_dir, page_dir, t_name);
    // };
    // const path base = data_dir / DATA_SUITE / "DoS_soft" / "expected_vht_beacon";
    // emit_table("5 GHz basic", base / "basic" / "basic_5GHz_filler", "basic_5GHz_filler");

    f << "</body>\n</html>\n";
}

}
