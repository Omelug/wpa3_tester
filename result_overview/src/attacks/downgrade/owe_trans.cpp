#include "attacks/downgrade/owe_trans.h"
#include <filesystem>
#include <string>
#include "suite/suite_helper.h"
#include "suite/downgrade/owe_trans_filler.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using suite::owe_trans_filler::OweTransTestEntry;

void generate_owe_trans(const path &output_dir, const path &data_dir) {

	const path page_dir = output_dir / "attacks" / "downgrade" / "owe_trans";
	create_public_dirs(page_dir);

	HtmlGuard f(page_dir);
	if (!f) return;

	f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>OWE Transition Probe Leak — Results</title>
	<link rel="stylesheet" href="../../../style.css">
	<script src="../../../table_aggregate.js"></script>
</head>
<body>
	<a href="../../../index.html" class="back-link"><- Overview</a>
	<h1>OWE Transition — Probe Request Leak</h1>

	<div class="card">
		<p><b>Prerequisites:</b> client connected to an OWE transition-mode AP (open + OWE BSS pair).</p>
		<p>After the OWE AP is stopped, a client with autoconnect will emit probe requests to rediscover
		   the network. Broadcast probes (empty SSID) reveal that the device is scanning; directed SSID probes
		   additionally reveal the preferred network name.</p>
		<p><b>Success:</b> at least one SSID probe request detected after AP shutdown.</p>
	</div>

	<div class="card">
		<h2>Mitigations</h2>
		<ul>
			<li>MAC address randomisation/li>
		</ul>
	</div>
)html";
	const path suite_dir = data_dir / DATA_SUITE / "downgrade" / "owe_trans" / "owe_trans_filler";

	auto emit_table = [&](const string &title, const path &suite_data_dir){
		OweTransTestEntry::render_table(f, title, suite_data_dir, page_dir);
	};

	emit_table("Test Results",  suite_dir);

	f << "</body>\n</html>\n";
}

}
