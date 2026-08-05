#include <array>
#include <filesystem>
#include <string>
#include "suite/suite_helper.h"
#include "suite/DoS_soft/bl0ck/bl0ck_test_suites.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using suite::bl0ck_test_suites::Bl0ckTestEntry;

void generate_bl0ck(const path &output_dir, const path &data_dir) {

    const path page_dir = output_dir / "attacks" / "DoS_soft" / "bl0ck";
    create_public_dirs(page_dir);

	HtmlGuard f(page_dir);
	if(!f) return;
//FIXME musí být opravdu fyzicky mezi nebo na vurnerable staří aby byl rychlejší jeden packet? 
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
    <a href="../../../index.html" class="back-link"><- Overview</a>
    <h1>Bl0ck — Block ACK (BA) DoS</h1>

    <div class="card">
        <p><b>prerequisites:</b> client connected to access point, QoS data used 802.11ac or 802.11ax, attacker needs to be physically between AP and client</p>
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

	auto emit_table = [&](const string &title, const path &suite_data_dir){
		Bl0ckTestEntry::render_table(f, title, suite_data_dir, page_dir);
	};

	const path bl0ck_base = data_dir / "wpa3_suites" / "DoS_soft" / "bl0ck";
	const array<string, 3> suite_fillers = {"BA_filler", "BAR_filler", "BARS_filler"};

	for (const auto &filler : suite_fillers){
		emit_table("Test Results", bl0ck_base / "suite" / filler);
	}
	emit_table("Dlink", bl0ck_base / "Dlink" / "bl0ck_Dlink_suite");

    f << "</body>\n</html>\n";
}

}
