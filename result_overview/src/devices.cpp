#include "devices.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "html_guard.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using json = nlohmann::json;

struct DeviceCaps {
	optional<bool> AP, STA, monitor;
	optional<bool> ghz2_4, ghz5, ghz6;
	optional<bool> n80211n, n80211ac, n80211ax;
	optional<bool> beacon_prot, CSA, OCV, MFP, WPA_PSK, WPA3_SAE;
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

static string json_str(const json &j, const string &key){
	if(j.contains(key) && j.at(key).is_string()) return j.at(key).get<string>();
	return {};
}

static optional<DeviceInfo> parse_device_file(const path &p, const string &mac){
	ifstream f(p);
	if(!f.is_open()) return nullopt;
	json j;
	try{ j = json::parse(f); } catch(const json::exception &){ return nullopt; }

	DeviceInfo d;
	d.mac    = mac;
	d.source = json_str(j, "source");
	d.name   = json_str(j, "actor_name");

	const json &caps = j.contains("caps") ? j.at("caps") : j;
	d.driver       = json_str(caps, "driver");
	d.driver_hash  = json_str(caps, "driver_hash");
	d.module_hash  = json_str(caps, "module_hash");
	d.caps.AP         = json_bool(caps, "AP");
	d.caps.STA        = json_bool(caps, "STA");
	d.caps.monitor    = json_bool(caps, "monitor");
	d.caps.ghz2_4     = json_bool(caps, "2_4GHz");
	d.caps.ghz5       = json_bool(caps, "5GHz");
	d.caps.ghz6       = json_bool(caps, "6GHz");
	d.caps.n80211n    = json_bool(caps, "80211n");
	d.caps.n80211ac   = json_bool(caps, "80211ac");
	d.caps.n80211ax   = json_bool(caps, "80211ax");
	d.caps.beacon_prot = json_bool(caps, "beacon_prot");
	d.caps.CSA        = json_bool(caps, "CSA");
	d.caps.OCV        = json_bool(caps, "OCV");
	d.caps.MFP        = json_bool(caps, "MFP");
	d.caps.WPA_PSK    = json_bool(caps, "WPA-PSK");
	d.caps.WPA3_SAE   = json_bool(caps, "WPA3-SAE");
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
	f << "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
	  << "    <meta charset=\"UTF-8\">\n"
	  << "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
	  << "    <title>Device: " << title << "</title>\n"
	  << "    <link rel=\"stylesheet\" href=\"../../style.css\">\n"
	  << "    <script src=\"../../table_aggregate.js\"></script>\n"
	  << "</head>\n<body>\n"
	  << "    <a href=\"../index.html\" class=\"back-link\">\xe2\x86\x90 Devices</a>\n"
	  << "    <h1>" << title << "</h1>\n"
	  << "    <div class=\"card\">\n        <h2>Identity</h2>\n        <table>\n"
	  << "            <tr><th>Permanent MAC</th><td>" << d.mac << "</td></tr>\n"
	  << "            <tr><th>Source</th><td>" << d.source << "</td></tr>\n"
	  << "            <tr><th>Driver</th><td>" << d.driver<< "</td></tr>\n";
	if(!d.driver_hash.empty()) f << "            <tr><th>Driver hash</th><td>" << d.driver_hash << "</td></tr>\n";
	if(!d.module_hash.empty()) f << "            <tr><th>Module hash</th><td>" << d.module_hash << "</td></tr>\n";
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
	     << "</td></tr>\n"
	  << "            <tr><th>Beacon protection</th><td>" << d.caps.beacon_prot << "</td></tr>\n"
	  << "            <tr><th>CSA</th><td>"    << d.caps.CSA     << "</td></tr>\n"
	  << "            <tr><th>OCV</th><td>"    << d.caps.OCV     << "</td></tr>\n"
	  << "            <tr><th>MFP</th><td>"    << d.caps.MFP     << "</td></tr>\n"
	  << "            <tr><th>WPA-PSK</th><td>"  << d.caps.WPA_PSK  << "</td></tr>\n"
	  << "            <tr><th>WPA3-SAE</th><td>" << d.caps.WPA3_SAE << "</td></tr>\n"
	  << "        </table>\n    </div>\n</body>\n</html>\n";
}

static void emit_section(HtmlGuard &f, const vector<DeviceInfo> &devices, const string &source){
	vector<const DeviceInfo *> rows;
	for(const auto &d : devices)
		if(d.source == source) rows.push_back(&d);

	if(rows.empty()){
		f << "        <p>No " << source << " devices recorded.</p>\n";
		return;
	}

	f << R"html(        <table class="aggregate">
            <thead><tr>
                <th>MAC</th><th>Driver</th>
                <th>AP</th><th>STA</th><th>Mon</th>
                <th>2.4G</th><th>5G</th><th>6G</th>
                <th>n</th><th>ac</th><th>ax</th>
                <th>Bcn</th><th>CSA</th><th>OCV</th><th>MFP</th><th>PSK</th><th>SAE</th>
            </tr></thead>
            <tbody>
)html";
	for(const auto *d : rows){
		const string label = d->name.empty() ? d->mac : d->name;
		f << "            <tr>\n"
		  << "                <td><a href=\"" << d->mac << "/index.html\">" << label << "</a></td>\n"
		  << "                <td>" << d->driver		 << "</td>\n"
		  << "                <td>" << d->caps.AP        << "</td>\n"
		  << "                <td>" << d->caps.STA       << "</td>\n"
		  << "                <td>" << d->caps.monitor   << "</td>\n"
		  << "                <td>" << d->caps.ghz2_4    << "</td>\n"
		  << "                <td>" << d->caps.ghz5      << "</td>\n"
		  << "                <td>" << d->caps.ghz6      << "</td>\n"
		  << "                <td>" << d->caps.n80211n   << "</td>\n"
		  << "                <td>" << d->caps.n80211ac  << "</td>\n"
		  << "                <td>" << d->caps.n80211ax  << "</td>\n"
		  << "                <td>" << d->caps.beacon_prot << "</td>\n"
		  << "                <td>" << d->caps.CSA       << "</td>\n"
		  << "                <td>" << d->caps.OCV       << "</td>\n"
		  << "                <td>" << d->caps.MFP       << "</td>\n"
		  << "                <td>" << d->caps.WPA_PSK   << "</td>\n"
		  << "                <td>" << d->caps.WPA3_SAE  << "</td>\n"
		  << "            </tr>\n";
	}
	f << "            </tbody>\n        </table>\n";
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
