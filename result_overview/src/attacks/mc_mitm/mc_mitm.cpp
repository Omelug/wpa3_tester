#include "attacks/mc_mitm/mc_mitm.h"
#include <filesystem>
#include <string>
#include "overview/html_utils.h"
#include "visual/mc_mitm/mc_mitm_filler.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using visual::mc_mitm_filler::McMitmEntry;

void generate_mc_mitm(const path &output_dir, const path &data_dir) {
    const path page_dir = output_dir / "attacks" / "mc_mitm" / "mc_mitm";
    create_public_dirs(page_dir);

    HtmlGuard f(page_dir);
    if (!f) return;

    f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>mc-mitm Attack — Results</title>
    <link rel="stylesheet" href="../../../style.css">
    <script src="../../../table_aggregate.js"></script>
</head>
<body>
    <a href="../../../index.html" class="back-link"><- Overview</a>
    <h1>Multi-Channel MitM (mc-mitm)</h1>

    <div class="card">
        <p><b>Prerequisites:</b> client connected to a legitimate AP, working CSA attack</p>
        <p>The attacker uses two wireless interfaces:
			<b>rogue_client</b> monitors the real channel and <b>rogue_ap</b> runs a rogue AP on a different channel.
			CSA beacons and deauth frames move the target client from the real AP to the rogue channel.
            Once the client associates with the rogue AP, traffic is forwarded through the attacker,
            achieving a transparent MitM position without breaking connectivity.</p>
        <p><b>Success:</b> client associates with the rogue AP (ClientState == GotMitm).</p>
    </div>

    <div class="card">
        <h2>Mitigations</h2>
        <ul>
            <li>Operating Channel Validation (OCV) — client verifies channel matches negotiated OCI</li>
        </ul>
    </div>

)html";

    McMitmEntry::render_table(f, "mc-mitm",
        data_dir / DATA_SUITE / "mc_mitm" / "mc_mitm" / "mc_mitm_filler",
        page_dir);

    f << "</body>\n</html>\n";
}

}
