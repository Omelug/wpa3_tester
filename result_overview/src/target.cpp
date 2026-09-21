#include "target.h"

#include "logger/log.h"
#include "page_cache.h"

#include <filesystem>
#include <map>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>

#include "overview/html_guard.h"
#include "system/utils.h"
#include "visual/DoS_hard/sae_dos/sae_dos_entry.h"
#include "visual/DoS_soft/bl0ck/bl0ck_test_suites.h"
#include "visual/DoS_soft/channel_switch/channel_switch_rogueAP.h"
#include "visual/DoS_soft/malformed_eapol1/malformed_eapol1_suite.h"
#include "visual/downgrade/owe_trans_filler.h"
#include "visual/downgrade/wpa3_downgrade_filler.h"
#include "visual/enterprise/invalid_curve/invalid_curve_filler.h"
#include "visual/enterprise/reflection_attack/reflection_attack_filler.h"
#include "visual/scan/ap_info_wpa3_filler.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using namespace visual;

static const map<string, string> k_attack_page = {
	{ "bl0ck", "../../attacks/DoS_soft/bl0ck/index.html" },
	{ "channel_switch", "../../attacks/DoS_soft/channel_switch/index.html" },
	{ "malformed_eapol1", "../../attacks/DoS_soft/malformed_eapol1/index.html" },
};

static string read_attacker_module(const path &test_folder) {
	const auto cfg = test_folder / "test_config.yaml";
	if(!exists(cfg)) return "";
	try {
		const auto node = YAML::LoadFile(cfg.string());
		if(node["attacker_module"]) return node["attacker_module"].as<string>();
	} catch(YAML::Exception &e) { log(LogLevel::ERROR, "Failed to load attacker module: {}", e.what()); }
	return "";
}

// last_run/{attack_dir}/{test_dir}/test_config.yaml
static vector<path> collect_test_folders(const path &run_dir) {
	vector<path> result;
	if(!is_directory(run_dir)) return result;
	for(const auto &attack_dir: directory_iterator(run_dir)) {
		if(!attack_dir.is_directory()) continue;
		for(const auto &test_dir: directory_iterator(attack_dir.path())) {
			if(!test_dir.is_directory()) continue;
			if(exists(test_dir.path() / "test_config.yaml")) result.push_back(test_dir.path());
		}
	}
	return result;
}

static void render_attack_section(HtmlGuard &f, const std::string &module, const std::string &attack_name,
		const path &suite_data_dir, const path &page_dir) {
	using namespace visual;

	static const std::unordered_map<std::string, RenderFunc> registry = {
		{ "ap_info", make_renderer<ap_info_wpa3_filler::ApInfoWpa3TestEntry>() },
		{ "bl0ck", make_renderer<bl0ck_test_suites::Bl0ckTestEntry>() },
		{ "invalid_curve", make_renderer<invalid_curve_filler::InvalidCurveTestEntry>() },
		{ "reflection_attack", make_renderer<reflection_attack_filler::ReflectionAttackTestEntry>() },
		{ "wpa3_trans_downgrade", make_renderer<wpa3_downgrade_filler::Wpa3TransDowngradeTestEntry>() },
		{ "owe_trans", make_renderer<owe_trans_filler::OweTransTestEntry>() },
		{ "channel_switch", make_renderer<channel_switch_rogueAP::CsaTestEntry>() },
		{ "malformed_eapol1", make_renderer<malformed_eapol1_filler::MalformedEapol1TestEntry>() },
		// DoS hard
		{ "cookie_guzzler", make_renderer<sae_dos::SaeDosFolderEntry>() },
		{ "memory_omnivore", make_renderer<sae_dos::SaeDosFolderEntry>() },
		{ "pmk_gobbler", make_renderer<sae_dos::SaeDosFolderEntry>() },
		//{ "sae_dos_wrapper",	 make_renderer<sae_dos::SaeDosFolderEntry>() },
	};

	if(const auto it = registry.find(module); it != registry.end()) {
		it->second(f, attack_name, suite_data_dir / attack_name, page_dir, module);
	} else {
		f << "<p>No parser for <code>" << module << "</code>.</p>";
	}
}

static void generate_target_page(const path &output_dir, const string &target_name, const path &target_data_dir) {
	const path page_dir = output_dir / "target" / target_name;

	HtmlGuard f(page_dir);

	f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>)html"
	  << target_name << R"html( - WPA3 Target Report</title>
	<link rel="stylesheet" href="../../style.css">
	<script src="../../table_aggregate.js"></script>
</head>
<body>
	<a href="../../index.html" class="back-link"><= Overview</a>
	<h1>)html"
	  << target_name << R"html(</h1>
)html";

	const path suites_dir = target_data_dir / "suite";
	if(!is_directory(suites_dir)) {
		f << "<div class=\"card\"><p>No suites found.</p></div>"
		  << "</body></html>";
		return;
	}

	bool any = false;
	for(const auto &suite_entry: directory_iterator(suites_dir)) {
		if(!suite_entry.is_directory()) continue;
		const string suite_name = suite_entry.path().filename().string();
		const auto test_suites_folders = collect_test_folders(suite_entry.path());
		if(test_suites_folders.empty()) continue;
		any = true;

		f << "<div class=\"card\">"
		  << "<h2>Suite: " << suite_name << "</h2>"
		  << "</div>";

		for(const auto &tf: test_suites_folders) {
			const auto mod = read_attacker_module(tf);
			if(mod.empty()) continue;
			const string attack_name = tf.parent_path().filename().string();
			render_attack_section(f, mod, attack_name, tf.parent_path(), page_dir);
		}
	}

	if(!any) f << "<div class=\"card\"><p>No test results found.</p></div>";
	f << "</body></html>";
}

static void generate_target_index(HtmlGuard &f, const vector<string> &targets) {
	f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Targets - WPA3 Tester</title>
	<link rel="stylesheet" href="../style.css">
</head>
<body>
	<a href="../index.html" class="back-link"><= Overview</a>
	<h1>Targets</h1>
	<div class="card">
		<ul>
)html";
	for(const auto &t: targets) f << "<li><a href=\"" << t << "/index.html\">" << t << "</a></li>";
	f << "</ul>\n    </div></body></html>";
}

void generate_targets(const path &output_dir, const path &data_dir) {
	const path targets_data = data_dir / DATA_SUITE / "comp";
	const path targets_dir = output_dir / "target";
	create_public_dirs(targets_dir);
	if(data_unchanged(targets_dir, targets_data)) return;

	vector<string> names;
	if(is_directory(targets_data)) {
		for(const auto &entry: directory_iterator(targets_data)) {
			if(!entry.is_directory()) continue;
			names.push_back(entry.path().filename().string());
		}
	}

	HtmlGuard f(targets_dir);
	generate_target_index(f, names);
	for(const auto &name: names)
		generate_target_page(output_dir, name, targets_data / name);
	update_data_stamp(targets_dir, targets_data);
}

}
