#include "attacks/DoS_soft/channel_switch.h"
#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>
#include "suite/suite_helper.h"
#include "suite/DoS_soft/channel_switch/channel_switch_rogueAP.h"
#include "system/utils.h"
#include "overview/html_utils.h"

namespace wpa3_tester::overview{
using namespace std;
using namespace filesystem;
using suite::channel_switch_rogueAP::CsaTestEntry;

static vector<CsaTestEntry> collect_results(const path &test_data_dir) {

	auto entries = suite::helper::collect_entries_nested(test_data_dir, [&test_data_dir](const path &p){
		auto e = CsaTestEntry::parse(p);
		e.rel_path = relative(p, test_data_dir);
		return e;
	});

	ranges::sort(entries, [](const CsaTestEntry& a, const CsaTestEntry& b) {
		const string sta_mac_a = a.client_mac;
		const string sta_mac_b = b.client_mac;
		if (sta_mac_a != sta_mac_b) return sta_mac_a < sta_mac_b;

		auto opt_rank = [](const optional<bool>& v) -> int {
		   return v.has_value() ? (*v ? 0 : 1) : 2;
		};
		//if (a.rel_path != b.rel_path) return a.rel_path < b.rel_path;

		const int ocv_a = opt_rank(a.ap_ocv.value()) + finite(opt_rank(a.client_ocv.value()));
		const int ocv_b = opt_rank(b.ap_ocv.value()) + opt_rank(b.client_ocv.value());
		if (ocv_a != ocv_b) return ocv_a < ocv_b;

		const int disc_a = opt_rank(a.client_disconnected.value());
		const int disc_b = opt_rank(b.client_disconnected.value());
		if (disc_a != disc_b) return disc_a < disc_b;

		return opt_rank(a.rogue_ap_connected) < opt_rank(b.rogue_ap_connected);
	});

	return entries;
}

void generate_channel_switch(const path &output_dir, const path &data_dir) {
	const path page_dir = output_dir / "attacks" / "DoS_soft" / "channel_switch";
	create_public_dirs(page_dir);

	HtmlGuard f(page_dir);
	if(!f) return;

	f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSA DoS Attack — Results</title>
    <link rel="stylesheet" href="../../../style.css">
    <script src="../../../table_aggregate.js"></script>
</head>
<body>
    <a href="../../../index.html" class="back-link"><- Overview</a>
    <h1>Channel Switch Announcement (CSA) DoS</h1>

    <div class="card">
        <p><b>prerequisites:</b> client connected to legit ap </p>
        <p>The attacker sends CSA beacons causing a connected client to switch
           Wi-Fi channels, disconnecting it from the legitimate AP.
           Optionally can attacker create rogue AP on new channel with WPA2 to downgrade and het WPA2 hash </p>
        <p><b>variants:</b> optionally attack can have rogue AP to check downgrade and WPA2 password<p>
        <p><b>success:</b> client disconnected from ap, in second variant try to connect to rogue AP</p>


    <img src="../../../images/CSA.svg" alt="CSA attack diagram" style="max-width:60%; margin-top:12px; display:block; margin-left:auto; margin-right:auto;">

        </div>
    <div class="card">
       <h2>Mitigations</h2>
<p>    OCV is protection, what add channel info (OCI) info into some frames, beacon protection is needed.
Not very supported, mobile devices have better support (//TODO add source)</p>
    </div>

)html";

	auto emit_table = [&](const string &title, const path &suite_data_dir){
		f	<< "	<div class=\"card\" style=\"overflow-x: auto;\">\n"
			<< "        <h2>"<< title << "</h2>\n";

		const auto results = collect_results(suite_data_dir);
		if(results.empty()){
			f << "<p>No test results found.</p>";
		}
		CsaTestEntry::render_table(f, results, page_dir);
		f << "    </div>\n";
	};

	// emit tables for each variant
	const path base = data_dir / "wpa3_suites" / "DoS_soft" / "channel_switch";

	emit_table("Test Results",  base / "rogueAP" / "CSA_rogueAP_internal_filler");
	emit_table("Dlink", base / "external" / "Dlink"   / "CSA_rogueAP_Dlink_filler");
	emit_table("External Client", base / "external" / "client"/ "CSA_external_client_filler");

	f << "</body>\n</html>\n";

}
}