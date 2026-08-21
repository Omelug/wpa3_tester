#include "attacks/mc_mitm/ssid_confusion.h"
#include <filesystem>
#include <string>
#include "overview/html_utils.h"
#include "visual/mc_mitm/ssid_confusion_filler.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using visual::ssid_confusion_filler::SsidConfusionEntry;

void generate_ssid_confusion(const path &output_dir, const path &data_dir) {
    const path page_dir = output_dir / "attacks" / "mc_mitm" / "ssid_confusion";
    create_public_dirs(page_dir);

    HtmlGuard f(page_dir);
    if (!f) return;

    f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSID Confusion Attack — Results</title>
    <link rel="stylesheet" href="../../../style.css">
    <script src="../../../table_aggregate.js"></script>
</head>
<body>
    <a href="../../../index.html" class="back-link"><- Overview</a>
    <h1>SSID Confusion Attack (CVE-2023-52424)</h1>

    <div class="card">
        <p><b>Prerequisites:</b> client connected to AP with SSID-A; client has SSID-B in its profile.</p>
        <p>The rogue AP clones the BSSID of the real AP but advertises SSID-B instead of SSID-A.
           Optionally the RSN IE is stripped so the network appears open.
           A client that auto-connects to SSID-B ends up associated with a network it did not intend to join,
           while believing it is on a trusted network.</p>
        <p><b>Success:</b> client associates with the rogue AP advertising the confused SSID (ClientState == GotMitm).</p>
    </div>

    <div class="card">
        <h2>Mitigations</h2>
        <ul>
            <li>IEEE 802.11 REVme amendment — SSID is included in the 4-way handshake (fixes CVE-2023-52424)</li>
            <li>Management Frame Protection (MFP / 802.11w) — prevents unauthenticated CSA/deauth used to move the client</li>
            <li>Beacon Protection — detects spoofed beacons with a different SSID</li>
        </ul>
    </div>

)html";

    SsidConfusionEntry::render_table(f, "ssid_confusion",
        data_dir / DATA_SUITE / "mc_mitm" / "ssid_confusion" / "ssid_confusion_filler",
        page_dir);

    f << "</body>\n</html>\n";
}

}
