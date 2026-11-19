// CVE-2020-24588: A-MSDU design flaw
//   Intercept encrypted AP->client QoS Data frame of known inner size,
//   flip A-MSDU Present bit (bit 7 of QoS byte 0, unauthenticated).
//   Client decrypts and misparses payload as A-MSDU subframes ->
//   second subframe (embedded by attacker's server) is processed as an
//   injected packet (e.g. ICMPv6 RA -> DNS poisoning).
//   Requires external server (amsdu_server.py) to send trigger IPv4 packet.
//
// CVE-2020-26144: Fake EAPOL plaintext A-MSDU
//   After MitM: inject a plaintext A-MSDU frame toward the real AP.
//   First 8 bytes of payload look like EAPOL LLC/SNAP (AA AA 03 00 00 00 88 8E),
//   so a vulnerable AP accepts the unencrypted frame.
//   AP then processes second subframe (ICMPv6 RA) and broadcasts it.
//   No external server needed.
#include "visual/mc_mitm/amsdu_filler.h"

#include <filesystem>
#include <string>

#include "config/RunSuiteStatus.h"
#include "default.h"
#include "logger/report.h"
#include "overview/html_guard.h"
#include "overview/html_utils.h"
#include "visual/result_helper.h"
#include "visual/suite_helper.h"

namespace wpa3_tester::visual::amsdu_filler {
using namespace std;
using namespace filesystem;

AmsduEntry AmsduEntry::parse(const path &test_folder) {
	auto e = helper::load_result_default<AmsduEntry>(test_folder);
	e.test_name = test_folder.filename().string();

	const auto rs = helper::load_test_rs(test_folder);

	const auto ap = rs->get_actor("ap");
	e.ap_mac = ap->get(SK::mac);

	const auto client = rs->get_actor("client");
	e.client_mac    = client->get(SK::mac);
	e.client_driver = client->get(SK::driver_name);

	const auto rogue_client = rs->get_actor("rogue_client");
	e.rogue_client_driver = rogue_client->get(SK::driver_name);

	const auto rogue_ap = rs->get_actor("rogue_ap");
	e.rogue_ap_driver = rogue_ap->get(SK::driver_name);

	e.ssid = rs->config().at("attack_config").at("ssid").get<string>();

	return e;
}

vector<AmsduEntry> AmsduEntry::collect_results(const path &suite_data_dir) {
	return helper::collect_entries_nested(suite_data_dir, [&suite_data_dir](const path &p) {
		auto e = parse(p);
		e.rel_path = relative(p, suite_data_dir);
		return e;
	});
}

void AmsduEntry::render_table(
	overview::HtmlGuard &f, const string &title, const path &suite_data_dir, const path &, const string &t_name) {

	helper::div_card<AmsduEntry>(
		f, title, suite_data_dir, [&](overview::HtmlGuard &hg, const vector<AmsduEntry> &entries) {
			HtmlPathTable t(hg, entries, t_name);
#define COL(name, body) col(name, [&]([[maybe_unused]] const auto &e) { hg << body; })
			t.build([&](auto col) {
				col("AP MAC",              &AmsduEntry::ap_mac);
				col("Client MAC",          &AmsduEntry::client_mac);
				col("Client driver",       &AmsduEntry::client_driver);
				col("rogue_client driver", &AmsduEntry::rogue_client_driver);
				col("rogue_ap driver",     &AmsduEntry::rogue_ap_driver);
				col("SSID",                &AmsduEntry::ssid);
				COL("MitM",         e.got_mitm);
				COL("26144 inject", e.injected_26144);
				COL("24588 flip",   e.flipped_24588);
				COL("DNS queried",  e.dns_queried);
			})->render();
#undef COL
		});
}

void AmsduEntry::generate_report(RunSuiteStatus &rss) {
	const auto run_dir = rss.run_folder();
	const auto entries = collect_results(run_dir);

	report::ReportGuard report(run_dir);
	if(!report) return;

	report << "# A-MSDU Attack Test Suite Report\n\n";
	report << "CVE-2020-26144 (plaintext EAPOL A-MSDU) and CVE-2020-24588 (A-MSDU flag flip).\n\n";

	if(entries.empty()) {
		report << "No test results found.\n";
		return;
	}

	report << "## Test Results\n\n";
	report << "| Test | AP MAC | Client MAC | Client driver | rogue_client | rogue_ap | MitM | 26144 inject | 24588 flip | DNS queried |\n";
	report << "|------|--------|------------|---------------|--------------|----------|:----:|:------------:|:----------:|:-----------:|\n";

	for(const auto &e: entries) {
		report << "| " << report::link(e.test_name, e.rel_path / REPORT_NAME)
			<< " | " << e.ap_mac
			<< " | " << e.client_mac
			<< " | " << e.client_driver
			<< " | " << e.rogue_client_driver
			<< " | " << e.rogue_ap_driver
			<< " | " << e.got_mitm
			<< " | " << e.injected_26144
			<< " | " << e.flipped_24588
			<< " | " << e.dns_queried
			<< " |\n";
	}
}

}
