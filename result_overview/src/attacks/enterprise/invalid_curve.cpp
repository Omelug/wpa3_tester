#include "system/utils.h"
#include "visual/enterprise/invalid_curve/invalid_curve_filler.h"
#include "visual/suite_helper.h"
#include <filesystem>
#include <string>

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;

void generate_invalid_curve_attack(const path &output_dir, const path &data_dir) {

	const path page_dir = output_dir / "attacks" / "enterprise" / "invalid_curve";
	create_public_dirs(page_dir);

	HtmlGuard f(page_dir);
	if (!f) return;

	f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title> Invalid curve </title>
	<link rel="stylesheet" href="../../../style.css">
	<script src="../../../table_aggregate.js"></script>
</head>
<body>
	<a href="../../../index.html" class="back-link"><- Overview</a>
	<h1>Invalid curve</h1>

	<div class="card">
		<p> #TODO invalid curve from pdf </p>
		<p><b>Success:</b> attacker connected </p>
	</div>

	<div class="card">
        <h2>Sources</h2>
        <ul>
            <li>https://github.com/vanhoefm/dragonslayer</li>
        </ul>
    </div>

)html";
	const path suite_dir = data_dir / DATA_SUITE / "enterprise" / "invalid_curve" / "invalid_curve_filler";

	auto emit_table = [&](const string &title, const path &suite_data_dir, const string &t_name) {
		visual::invalid_curve_filler::InvalidCurveTestEntry::render_table(
			f, title, suite_data_dir, page_dir, t_name);
	};

	emit_table("Test Results",  suite_dir, "invalid_curve_filler");

	f << "</body>\n</html>\n";
}

}
