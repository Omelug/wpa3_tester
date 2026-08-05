#include "attacks/DoS_soft/malformed_eapol1.h"
#include <filesystem>
#include "suite/DoS_soft/malformed_eapol1/malformed_eapol1_suite.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using suite::malformed_eapol1_filler::MalformedEapol1TestEntry;

void generate_malformed_eapol1(const path &output_dir, const path &data_dir) {
    const path page_dir = output_dir / "attacks" / "DoS_soft" / "malformed_eapol1";
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
    <a href="../../../index.html" class="back-link"><- Overview</a>
    <h1>Malformed EAPOL Key Frame DoS</h1>

    <div class="card">
        <p><b>prerequisites:</b> client attempting WPA3 handshake with access point</p>
        <p>The attacker injects a malformed EAPOL 1 Key frame (invalid tag length) during
           the 4-way handshake, causing the client to disconnect.</p>
        <p><b>success:</b> client disconnected from access point</p>
    </div>

)html";

	auto emit_table = [&](const string &title, const path &suite_data_dir){
		MalformedEapol1TestEntry::render_table(f, title, suite_data_dir, page_dir);
	};

	// emit tables for each variant
	const path base = data_dir / "wpa3_suites" / "DoS_soft" / "channel_switch";

	emit_table("Test Results",
		data_dir / "wpa3_suites" / "DoS_soft" / "malformed_eapol1" / "malformed_eapol1_basic_suite");
	emit_table("Dlink",
		data_dir / "wpa3_suites" / "DoS_soft" / "malformed_eapol1" / "external" / "m_eapol1__rogueAP_Dlink_filler");


    f << "</body>\n</html>\n";
}

}
