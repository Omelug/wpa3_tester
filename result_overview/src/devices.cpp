#include "devices.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

#include "overview/html_guard.h"
#include "overview/html_utils.h"
#include "suite/result_helper.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using json = nlohmann::json;

//TODO rewrite this ti Html Guard / deafulet json

struct DeviceCaps {
	optional<bool> AP, STA, monitor;
	optional<bool> ghz2_4, ghz5, ghz6;
	optional<bool> n80211n, n80211ac, n80211ax;
	optional<bool> netns_change, beacon_prot, CSA, OCV, MFP, WPA_PSK, WPA3_SAE;
};

struct DeviceInfo {
	string mac;
	string source;
	string name;
	string driver;
	string driver_hash;
	string module_hash;
	DeviceCaps caps;
};

static optional<bool> json_bool(const json &j, const string &key){
	if(j.contains(key) && j.at(key).is_boolean()) return j.at(key).get<bool>();
	return nullopt;
}

static optional<DeviceInfo> parse_device_file(const path &p, const string &mac){
	ifstream f(p);
	if(!f.is_open()) return nullopt;
	json j;
	try{ j = json::parse(f); } catch(const json::exception &){ return nullopt; }

	const json &caps = j.contains("caps") ? j.at("caps") : j;
	DeviceInfo d;
	d.mac         = mac;
	d.source      = j.value("source", string{});
	d.name        = j.value("actor_name", string{});
	d.driver      = caps.value("driver", string{});
	d.driver_hash = caps.value("driver_hash", string{});
	d.module_hash = caps.value("module_hash", string{});
	d.caps        = suite::helper::load_result_default<DeviceCaps>(caps);

	// JSON keys here aren't valid C++ identifiers so pfr can't map them by name
	d.caps.ghz2_4  = json_bool(caps, "2_4GHz");
	d.caps.ghz5    = json_bool(caps, "5GHz");
	d.caps.ghz6    = json_bool(caps, "6GHz");
	d.caps.n80211n  = json_bool(caps, "80211n");
	d.caps.n80211ac = json_bool(caps, "80211ac");
	d.caps.n80211ax = json_bool(caps, "80211ax");
	d.caps.WPA_PSK  = json_bool(caps, "WPA-PSK");
	d.caps.WPA3_SAE = json_bool(caps, "WPA3-SAE");
	return d;
}

static optional<DeviceInfo> read_device(const path &dev_dir){
	const string mac = dev_dir.filename().string();
	const path last = dev_dir / "last.json";
	if(exists(last)){
		if(auto d = parse_device_file(last, mac); d.has_value()) return d;
	}
	// fallback: newest .json by name (timestamps sort lexicographically)
	vector<path> jsons;
	for(const auto &e : directory_iterator(dev_dir))
		if(e.is_regular_file() && e.path().extension() == ".json") jsons.push_back(e.path());
	if(jsons.empty()) return nullopt;
	ranges::sort(jsons);
	return parse_device_file(jsons.back(), mac);
}

static void generate_device_page(const path &devices_dir, const DeviceInfo &d){
	const path page_dir = devices_dir / d.mac;
	create_public_dirs(page_dir);
	HtmlGuard f(page_dir);
	if(!f) return;

	const string title = d.name.empty() ? d.mac : d.name;
	auto tr = [&](string_view key, const auto &val){
		f << "            <tr><th>" << key << "</th><td>" << val << "</td></tr>\n";
	};

	f << "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
	  << "    <meta charset=\"UTF-8\">\n"
	  << "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
	  << "    <title>Device: " << title << "</title>\n"
	  << "    <link rel=\"stylesheet\" href=\"../../style.css\">\n"
	  << "    <script src=\"../../table_aggregate.js\"></script>\n"
	  << "</head>\n<body>\n"
	  << "    <a href=\"../index.html\" class=\"back-link\">\xe2\x86\x90 Devices</a>\n"
	  << "    <h1>" << title << "</h1>\n"
	  << "    <div class=\"card\">\n        <h2>Identity</h2>\n        <table>\n";
	tr("Permanent MAC", d.mac);
	tr("Source",        d.source);
	tr("Driver",        d.driver);
	if(!d.driver_hash.empty()) tr("Driver hash", d.driver_hash);
	if(!d.module_hash.empty()) tr("Module hash", d.module_hash);
	f << "        </table>\n    </div>\n"
	  << "    <div class=\"card\">\n        <h2>Capabilities</h2>\n        <table>\n"
	  << "            <tr><th>Mode</th><td>"
	     << "AP: " << d.caps.AP << " &nbsp; STA: " << d.caps.STA << " &nbsp; Monitor: " << d.caps.monitor
	     << "</td></tr>\n"
	  << "            <tr><th>Bands</th><td>"
	     << "2.4 GHz: " << d.caps.ghz2_4 << " &nbsp; 5 GHz: " << d.caps.ghz5 << " &nbsp; 6 GHz: " << d.caps.ghz6
	     << "</td></tr>\n"
	  << "            <tr><th>Standards</th><td>"
	     << "802.11n: " << d.caps.n80211n << " &nbsp; 802.11ac: " << d.caps.n80211ac << " &nbsp; 802.11ax: " << d.caps.n80211ax
	     << "</td></tr>\n";
	tr("Beacon protection", d.caps.beacon_prot);
	tr("CSA",              d.caps.CSA);
	tr("OCV",              d.caps.OCV);
	tr("MFP",              d.caps.MFP);
	tr("WPA-PSK",          d.caps.WPA_PSK);
	tr("WPA3-SAE",         d.caps.WPA3_SAE);
	f << "        </table>\n    </div>\n</body>\n</html>\n";
}

static void emit_section(HtmlGuard &f, const vector<DeviceInfo> &devices, const string &source){
	vector<DeviceInfo> rows;
	ranges::copy_if(devices, back_inserter(rows), [&](const auto &d){ return d.source == source; });

	if(rows.empty()){
		f << "        <p>No " << source << " devices recorded.</p>\n";
		return;
	}

	#define COL(h, expr) col(h, [&]([[maybe_unused]] const DeviceInfo &d){ f << (expr); })

	HtmlPathTable(f, rows).build([&](auto col){
		col("MAC", [&](const DeviceInfo &d){
			const string label = d.name.empty() ? d.mac : d.name;
			f << "<a href=\"" << d.mac << "/index.html\">" << label << "</a>";
		});
		COL("Driver",      d.driver);
		COL("AP",          d.caps.AP);
		COL("STA",         d.caps.STA);
		COL("Mon",         d.caps.monitor);
		COL("2.4G",        d.caps.ghz2_4);
		COL("5G",          d.caps.ghz5);
		COL("6G",          d.caps.ghz6);
		COL("n",           d.caps.n80211n);
		COL("ac",          d.caps.n80211ac);
		COL("ax",          d.caps.n80211ax);
		COL("netns change",d.caps.netns_change);
		COL("Bcn",         d.caps.beacon_prot);
		COL("CSA",         d.caps.CSA);
		COL("OCV",         d.caps.OCV);
		COL("MFP",         d.caps.MFP);
		COL("PSK",         d.caps.WPA_PSK);
		COL("SAE",         d.caps.WPA3_SAE);
	})->render();
#undef COL
}

void generate_devices(const path &output_dir, const path &data_dir){
	const path dev_data   = data_dir / "devices";
	const path devices_dir = output_dir / "devices";
	create_public_dirs(devices_dir);

	vector<DeviceInfo> devices;
	if(exists(dev_data) && is_directory(dev_data)){
		for(const auto &entry : directory_iterator(dev_data)){
			if(!entry.is_directory()) continue;
			if(auto d = read_device(entry.path()); d.has_value())
				devices.push_back(std::move(*d));
		}
	}

	ranges::sort(devices, [](const DeviceInfo &a, const DeviceInfo &b){
		if(a.source != b.source) return a.source < b.source;
		return a.name < b.name;
	});

	for(const auto &d : devices)
		generate_device_page(devices_dir, d);

	HtmlGuard f(devices_dir);
	if(!f) return;

	f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Devices</title>
	<link rel="stylesheet" href="../style.css">
	<script src="../table_aggregate.js"></script>
</head>
<body>
	<a href="../index.html" class="back-link">&#8592; Overview</a>
	<h1>Devices</h1>
)html";

	constexpr array<pair<string_view, string_view>, 3> sections = {{
		{"External",   "external"},
		{"Internal",   "internal"},
		{"Simulation", "simulation"},
	}};
	for(const auto &[label, src] : sections){
		f << "    <div class=\"card\">\n        <h2>" << label << "</h2>\n";
		emit_section(f, devices, string(src));
		f << "    </div>\n";
	}

	f << "</body>\n</html>\n";
}

}
