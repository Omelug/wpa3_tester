#include "attacks/downgrade/owe_trans.h"
#include "suite/downgrade/owe_trans_filler.h"
#include "suite/enterprise/invalid_curve/invalid_curve_filler.h"
#include "suite/enterprise/reflection_attack/reflection_attack_filler.h"
#include "suite/suite_helper.h"
#include "system/utils.h"
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
	<h1>Reflection at</h1>

	<div class="card">

#TODO info about both directions

		<p> Some APs accept same PWE what is send by them - but still dont crack the password</p>
		<p><b>Success:</b> attacker connected </p>
	</div>

)html";
	const path suite_dir = data_dir / DATA_SUITE / "enterprise" / "reflection_attack" / "reflection_attack_filler";

	auto emit_table = [&](const string &title, const path &suite_data_dir) {
		suite::reflection_attack_filler::ReflectionAttackTestEntry::render_table(f, title, suite_data_dir, page_dir);
	};

	emit_table("Test Results",  suite_dir);

	f << "</body>\n</html>\n";
}

}
