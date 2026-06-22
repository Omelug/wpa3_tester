#include "attacks/DoS_soft/channel_switch.h"
#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>
#include "html_guard.h"
#include "suite/suite_helper.h"
#include "suite/DoS_soft/channel_switch/channel_switch_rogueAP.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using suite::channel_switch_rogueAP::CsaTestEntry;

using TaggedEntry = pair<string, CsaTestEntry>;

static vector<TaggedEntry> collect_results(const path &data_dir) {
	const path base = data_dir / "wpa3_suites" / "DoS_soft" / "channel_switch";

	const array<pair<string, path>, 2> sources = {{
		{"internal", base / "rogueAP" / "CSA_rogueAP_internal_filler"},
		{"Dlink",    base / "Dlink"   / "CSA_rogueAP_Dlink_filler"},
	}};

	vector<TaggedEntry> results;
	for (const auto &[variant, suite_dir] : sources) {
		for (const auto &src_dir : suite::helper::get_suite_test_folders(suite_dir)) {
			for (const auto &entry : directory_iterator(src_dir)) {
				if (!entry.is_directory()) continue;
				auto e = suite::channel_switch_rogueAP::parse_test_folder(entry.path());
				results.emplace_back(variant, std::move(e));
			}
		}
	}

	ranges::sort(results, [](const TaggedEntry& a, const TaggedEntry& b) {
		auto opt_rank = [](const optional<bool>& v) -> int {
		   return v.has_value() ? (*v ? 0 : 1) : 2;
		};
		if (a.first != b.first) return a.first < b.first;

		const int ocv_a = opt_rank(a.second.ap_ocv) + opt_rank(a.second.client_ocv);
		const int ocv_b = opt_rank(b.second.ap_ocv) + opt_rank(b.second.client_ocv);
		if (ocv_a != ocv_b) return ocv_a < ocv_b;

		const int disc_a = opt_rank(a.second.disconnected);
		const int disc_b = opt_rank(b.second.disconnected);
		if (disc_a != disc_b) return disc_a < disc_b;

		return opt_rank(a.second.rogue_ap_connected) < opt_rank(b.second.rogue_ap_connected);
	});

	return results;
}

void generate_channel_switch(const path &output_dir, const path &data_dir) {
    const auto results = collect_results(data_dir);  // vector<TaggedEntry>

    const path page_dir = output_dir / "attacks" / "dos_soft" / "channel_switch";
    create_public_dirs(page_dir);
    const path img_dir = page_dir / "img";

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
    <a href="../../../index.html" class="back-link">← Overview</a>
    <h1>Channel Switch Announcement (CSA) DoS</h1>

    <div class="card">
		<p><b>prerequisites:</b> client connected to legit access_point </p>
        <p>The attacker sends CSA beacons causing a connected client to switch
           Wi-Fi channels, disconnecting it from the legitimate AP.
		   Optionally can attacker create rogue AP on new channel with WPA2 to downgrade and het WPA2 hash </p>
		<p><b>variants:</b> optionally attack can have rogue AP to check downgrade and WPA2 password<p>
		<p><b>success:</b> client disconnected from access_point, in second variant try to connect to rogue AP</p>


<img src="../../../images/CSA.svg" alt="CSA attack diagram" style="max-width:60%; margin-top:12px; display:block; margin-left:auto; margin-right:auto;">

	</div>
<div class="card">
	   <h2>Mitigations</h2>
<p>	OCV is protection, what add channel info (OCI) info into some frames, beacon protection is needed.
Not very supported, mobile devices have better support (//TODO add source)</p>
</div>

)html";

    auto emit_table = [&](const string &title, const string &table_id, const string &variant_filter) {
        vector<const CsaTestEntry*> rows;
        for (const auto &[variant, e] : results)
            if (variant == variant_filter) rows.push_back(&e);

        if (rows.empty()) return;

        f << "    <div class=\"card\" style=\"overflow-x: auto;\">\n"
          << "        <h2>" << title << "</h2>\n"
          << "        <table id=\"" << table_id << "\" class=\"aggregate\">\n"
          << "            <thead><tr>\n"
          << "                <th>AP MAC (source)</th>\n"
          << "                <th>Client MAC (source)</th>\n"
          << "                <th>Attacker MAC (driver) <br> RogueAP MAC (driver)\n"
          << "                <th>Disconnected? <br> (from AP view)</th>\n"
          << "                <th>Rogue AP?</th>\n"
          << "                <th>AP OCV / Client OCV</th>\n"
          << "                <th>Client MFP</th>\n"
          << "            </tr></thead>\n"
          << "            <tbody>\n";
        for (const auto *e : rows) {
            f << "                <tr>\n";
            f << "                    <td>" << device(e->ap_mac, page_dir)   << " (" << e->ap_source     << ")</td>\n";
            f << "                    <td>" << device(e->client_mac, page_dir) << " (" << e->client_source << ")</td>\n";
            f << "                    <td>" << device(e->attacker_mac, page_dir) << " (" << e->attacker_driver << ")";
            if (!e->rogue_ap_mac.empty() || !e->rogue_ap_driver.empty())
                f << "<br>" << e->rogue_ap_mac << " (" << e->rogue_ap_driver << ")";
            f << "</td>\n";
            f << "                    <td>" << e->disconnected << " (" << e->ap_disconnected << ")</td>\n";
            f << "                    <td>" << e->rogue_ap_connected     << "</td>\n";
            f << "                    <td>" << e->ap_ocv << " / " << e->client_ocv << "</td>\n";
            f << "                    <td>" << e->client_mfp << "</td>\n";
            f << "                </tr>\n";
        }
        f << "            </tbody>\n        </table>\n    </div>\n";
    };

    if (results.empty()) {
        f << "    <div class=\"card\"><p>No test results found.</p></div>\n";
    } else {
        emit_table("Test Results", "resultsTable", "internal");
        emit_table("Dlink", "resultsTableDlink", "Dlink");
    }

    f << "</body>\n</html>\n";

}

}
