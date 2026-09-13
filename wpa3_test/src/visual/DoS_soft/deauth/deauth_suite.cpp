#include <filesystem>

#include "config/RunSuiteStatus.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/report.h"
#include "overview/html_utils.h"
#include "visual/DoS_soft/deauth/deauth_suite.h"
#include "visual/result_helper.h"
#include "visual/suite_helper.h"

namespace wpa3_tester::visual::deauth_suite {
using namespace std;
using namespace filesystem;

DeauthTestEntry DeauthTestEntry::parse(const path &test_folder) {
	auto e = helper::load_result_default<DeauthTestEntry>(test_folder);
	e.test_name = test_folder.filename().string();

	const auto rs = helper::load_test_rs(test_folder);
	if(!rs) return e;

	const auto ap = rs->get_actor("ap");
	e.ap_mac = ap->get(SK::mac);
	e.ap_source = ap->get(SK::source);
	e.ap_driver = ap->get(SK::driver_name);

	const auto client = rs->get_actor("client");
	e.client_mac = client->get(SK::mac);
	e.client_source = client->get(SK::source);
	e.client_driver = client[SK::driver_name];
	e.client_version = hostapd::get_version(*rs, "client");

	const auto att = rs->get_actor("attacker");
	e.attacker_mac = att->get(SK::mac);
	e.attacker_driver = att->get(SK::driver_name);

	return e;
}

vector<DeauthTestEntry> DeauthTestEntry::collect_results(const path &test_data_dir) {
	auto entries = helper::get_results_default<DeauthTestEntry>(test_data_dir);
	ranges::sort(entries, [](const DeauthTestEntry &a, const DeauthTestEntry &b) {
		return tie(a.client_version, a.client_mfp, a.ap_mac) < tie(b.client_version, b.client_mfp, b.ap_mac);
	});
	return entries;
}

void DeauthTestEntry::render_table(overview::HtmlGuard &f, const string &title, const path &suite_data_dir,
		const path &page_dir, const string &t_name) {

	helper::div_card<DeauthTestEntry>(
			f, title, suite_data_dir, [&](overview::HtmlGuard &hg, const vector<DeauthTestEntry> &entries) {
				HtmlPathTable t(hg, entries, t_name);
#define COL(name, body) col(name, [&]([[maybe_unused]] const auto &e) { hg << body; })
				t.build([&](auto col) {
					 col("Test", &DeauthTestEntry::test_name);
					 COL("AP MAC (source)", overview::device(e.ap_mac, page_dir) << " (" << e.ap_source << ")");
					 COL("Client MAC (source)",
							 overview::device(e.client_mac, page_dir) << " (" << e.client_source << ")");
					 col("wpa_supplicant version", &DeauthTestEntry::client_version);
					 COL("Disconnected? (client/AP)", e.client_disconnected << " (" << e.ap_disconnected << ")");
					 col("Client MFP", &DeauthTestEntry::client_mfp);
					 COL("AP/Client WPA support", e.ap_WPA_support << "<br>" << e.client_WPA_support);
					 col("Connected WPA version", &DeauthTestEntry::conn_WPA_version);
				 })->render({ "Test" });
#undef COL
			});
}

void DeauthTestEntry::generate_report(const RunSuiteStatus &rss) {
	const auto entries = helper::get_results_default<DeauthTestEntry>(rss.run_folder());

	report::ReportGuard report(rss.run_folder());
	if(!report) return;

	report << "# Deauth DoS Attack Suite Report (hostapd 2019-7)\n\n";
	report << "Exploits hostapd security advisory 2019-7: deauth with SA == AP own addr causes\n"
			  "hostapd to disconnect its own clients, bypassing PMF. Fixed in hostapd >= 2.10.\n"
			  "https://w1.fi/security/2019-7/\n\n";

	if(entries.empty()) {
		report << "No test results found.\n";
		return;
	}

	report << "## Results\n\n";
	report << "| Test | AP Driver | Client Driver | Client Version | Disconnected |\n";
	report << "|------|-----------|---------------|----------------|--------------|\n";
	for(const auto &e: entries) {
		report << "| " << report::link(e.test_name, path(e.test_name) / REPORT_NAME) << " | " << e.ap_driver << " | "
			   << e.client_driver.value_or("N/A") << " | " << e.client_version << " | " << e.client_disconnected
			   << " |\n";
	}
}

}
