#include "system/utils.h"
#include "visual/enterprise/reflection_attack/reflection_attack_filler.h"
#include "visual/suite_helper.h"
#include <filesystem>
#include <string>

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;

void generate_reflection_attack(const path &output_dir, const path &data_dir) {

	const path page_dir = output_dir / "attacks" / "enterprise" / "reflection_attack";
	create_public_dirs(page_dir);

	HtmlGuard f(page_dir);
	if (!f) return;

	f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title> Reflection attack</title>
	<link rel="stylesheet" href="../../../style.css">
	<script src="../../../table_aggregate.js"></script>
</head>
<body>
	<a href="../../../index.html" class="back-link"><- Overview</a>
	<h1>Reflection attack</h1>

	<div class="card">

#TODO info about both directions
		<p><b>Info:</b> https://github.com/vanhoefm/dragonslayer </p>
		<p> Some APs accept same PWE what is send by them </p>
		<p><b>Success:</b> attacker connected without password (Attacker dont gain password )</p>
	</div>

)html";
	const path suite_dir = data_dir / DATA_SUITE / "enterprise" / "reflection_attack" / "reflection_attack_filler";

	auto emit_table = [&](const string &title, const path &suite_data_dir, const string &t_name) {
		visual::reflection_attack_filler::ReflectionAttackTestEntry::render_table(f, title, suite_data_dir, page_dir, t_name);
	};

	emit_table("Test Results",  suite_dir,  "reflection_attack_filler");

	f << "</body>\n</html>\n";
}

}
