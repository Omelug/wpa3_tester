#include "attacks/downgrade/wpa3_trans_downgrade.h"
#include <filesystem>
#include <string>
#include "suite/suite_helper.h"
#include "suite/downgrade/wpa3_downgrade_filler.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using suite::wpa3_downgrade_filler::Wpa3TransDowngradeTestEntry;

void generate_wpa3_trans_downgrade(const path &output_dir, const path &data_dir) {

	const path page_dir = output_dir / "attacks" / "downgrade" / "wpa3_trans_downgrade";
	create_public_dirs(page_dir);

	HtmlGuard f(page_dir);
	if (!f) return;

	f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>WPA3 Transition Downgrade — Results</title>
	<link rel="stylesheet" href="../../../style.css">
	<script src="../../../table_aggregate.js"></script>
</head>
<body>
	<a href="../../../index.html" class="back-link"><- Overview</a>
	<h1>WPA3 Transition — Downgrade to WPA2-PSK</h1>

	<div class="card">
		<p><b>Prerequisites:</b> client connected to a WPA3-Transition AP (SAE+PSK).</p>
		<p>A rogue WPA2-PSK-only AP with the same SSID is running</p>
		<p>After the legitimate AP is stopped, a vulnerable client automatically associates using WPA2-PSK, completing a downgrade attack.</p>
		<p><b>Success:</b> client send valid hash to rogue WPA2-PSK AP.</p>
	</div>

	<div class="card">
		<h2>Mitigations</h2>
		<ul>
			<li>Enforce SAE-only association (disable PSK fallback)</li>
			<li>WPA3-only mode (no transition mode)</li>
		</ul>
	</div>
)html";
	const path suite_dir = data_dir / DATA_SUITE / "downgrade" / "wpa3_down" / "wpa3_downgrade_filler";

	auto emit_table = [&](const string &title, const path &suite_data_dir){
		Wpa3TransDowngradeTestEntry::render_table(f, title, suite_data_dir, page_dir);
	};

	emit_table("filler", suite_dir);

	f << "</body>\n</html>\n";
}

}
