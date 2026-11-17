#include "attacks/two_iface/active_monitor_overview.h"
#include "overview/html_guard.h"
#include "overview/html_utils.h"
#include "page_cache.h"
#include "visual/suite_helper.h"
#include "visual/two_iface/active_test_filler.h"
#include <filesystem>

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using visual::active_test_filler::ActiveTestEntry;

void generate_active_monitor_overview(const path &output_dir, const path &data_dir) {
	const path page_dir = output_dir / "attacks" / "two_iface" / "active_monitor";
	const path base = data_dir / DATA_SUITE / "two_iface" / "active_test" / "active_test_filler";
	if(data_unchanged(page_dir, base)) return;

	HtmlGuard hg(page_dir);

	hg << R"html(<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Active Monitor Test</title>
	<link rel="stylesheet" href="../../../style.css">
	<script src="../../../table_aggregate.js"></script>
</head>
<body>
	<a href="../../../index.html" class="back-link"><= Overview</a>
	<h1>Active Monitor Test</h1>
	<div class="card">
		<p>Tests whether a monitor-mode interface (transceiver) can inject frames
		   and receive ACKs via an active-monitor interface (receiver).</p>
		<p><b>Success:</b> more than percentage threshold of injected frames acknowledged.</p>
	</div>
	<div class="card">
)html";

	const auto entries = visual::helper::get_results_default<ActiveTestEntry>(base);

	auto render_table = [&](const vector<ActiveTestEntry> &rows, const string &title) {
		if(rows.empty()) return;
		hg << "<h2>" << title << "</h2>";
		HtmlPathTable table(hg, rows, string("active_test_filler"));
#define COL(name, body) col(name, [&]([[maybe_unused]] const auto &e) { hg << body; })
		table.build([&](auto col) {
			col("Test",       &ActiveTestEntry::test_name);
			col("TX Driver",  &ActiveTestEntry::tx_driver);
			COL("Client MAC (source)", overview::device(e.rx_mac, page_dir) << " (" << e.rx_driver << ")" );
			col("Acked",      &ActiveTestEntry::acked);
			col("Not Acked",  &ActiveTestEntry::not_acked);
			col("Success", &ActiveTestEntry::success);
		})->render({ "Test" });
#undef COL
	};

	if(entries.empty()) {
		hg << "<p>No results found. Run active_test_filler to populate.</p>";
	} else {
		vector<ActiveTestEntry> base_entries, spoofed_entries;
		for(const auto &e: entries)
			(e.test_name.contains("spoof") ? spoofed_entries : base_entries).push_back(e);
		render_table(base_entries,    "Standard");
		render_table(spoofed_entries, "Spoofed MAC");
	}

	hg << "</div></body></html>";
	write_data_stamp(page_dir, base);
}

}
