#include "attacks/DoS_soft/channel_switch.h"
#include <filesystem>
#include <string>
#include "overview/html_utils.h"
#include "suite/DoS_soft/channel_switch/channel_switch_rogueAP.h"
#include "system/utils.h"

namespace wpa3_tester::overview{
using namespace std;
using namespace filesystem;
using suite::channel_switch_rogueAP::CsaTestEntry;

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
		CsaTestEntry::render_table(f, title, suite_data_dir, page_dir);
	};

	// emit tables for each variant
	const path base = data_dir / DATA_SUITE / "DoS_soft" / "channel_switch";

	emit_table("RogueAP ",  base / "rogueAP" / "CSA_rogueAP_internal_filler");
	emit_table("Dlink", base / "external" / "Dlink"   / "CSA_rogueAP_Dlink_filler");
	emit_table("External Client", base / "external" / "client"/ "CSA_external_client_filler");

	f << "</body>\n</html>\n";

}
}