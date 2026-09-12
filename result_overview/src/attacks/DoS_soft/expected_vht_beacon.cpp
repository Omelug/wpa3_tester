#include "attacks/DoS_soft/expected_vht_beacon.h"
#include "overview/html_utils.h"
#include "system/utils.h"
#include "visual/DoS_soft/expected_vht_beacon/expected_vht_beacon_suite.h"
#include <filesystem>
#include <string>

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using visual::expected_vht_beacon_suite::ExpVhtTestEntry;

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
    <h1> fake legacy beacon DoS </h1>

    <div class="card">
        <p><b>prerequisites:</b> client connected to a VHT (802.11ac) access point</p>
        <p>
			The attacker captures the real AP beacon, strips
            <code>VHT_CAP</code> and <code>VHT_OP</code> IEs, and re-injects
            it on the AP's BSSID. The mac80211 kernel driver detects that the AP
            appears to have switched from VHT to legacy mode and forcibly disconnects
            the client (AP appears to change mode (expected HT/VHT, found legacy))
			- code in mac80211 https://github.com/torvalds/linux/blob/master/net/mac80211/mlme.c
        </p>
        <p>
            On mt76x2u this is also a side-effect of the Bl0ck/BARS attack.
        </p>
        <p><b>success:</b>
			client receives fake legacy beacon and disconnects from the AP
		</p>
    </div>

    <div class="card">
        <h2>Mitigations</h2>
        <ul>
            <li><b>Beacon Protection (BIGTK, 802.11ax)</b> — fake beacons without a valid
                BIP-CMAC-256 tag are silently dropped. Not yet widely deployed.</li>
        </ul>
    </div>

	<div class="card">
        <h2>Sources</h2>
        <ul>
            <li>https://github.com/domienschepers/wifi-framework/blob/master/test-dos.py</li>
        </ul>
    </div>

)html";

    auto emit_table = [&](const string &title, const path &suite_data_dir, const string &t_name) {
        ExpVhtTestEntry::render_table(f, title, suite_data_dir, page_dir, t_name);
    };

    const path base = data_dir / DATA_SUITE / "DoS_soft" / "expected_vht_beacon";

    emit_table("2.4 GHz", base / "basic" / "expected_vht_beacon_2_4GHz_filler", "expected_vht_beacon_2_4GHz_filler");
    emit_table("5 GHz",   base / "basic" / "expected_vht_beacon_5GHz_filler",   "expected_vht_beacon_5GHz_filler");
    emit_table("RogueAP (2.4 GHz)", base / "rogueAP" / "expected_vht_beacon_rogueAP_filler", "expected_vht_beacon_rogueAP_filler");

    f << "</body>\n</html>\n";
}

}
