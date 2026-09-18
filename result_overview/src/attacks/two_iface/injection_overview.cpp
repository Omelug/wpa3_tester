#include "attacks/two_iface/injection_overview.h"
#include "overview/html_guard.h"
#include "overview/html_utils.h"
#include "system/utils.h"
#include <filesystem>
#include <fstream>
#include <map>
#include <nlohmann/json.hpp>
#include <set>
#include <algorithm>

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using nlohmann::json;

struct InjectionCacheEntry {
    string tx_mac;
    string rx_mac;
    string driver;
    string rx_driver;
    map<string, pair<string,string>> tests; // test_name -> {result, detail}
};

static string result_cell(const string &r, const string &detail = "") {
    const string d = detail.empty() ? "" : " data-detail=\"" + detail + "\"";
    if(r == "PASSED")    return "<span class=\"it-pass\"" + d + ">P</span>";
    if(r == "FAIL")      return "<span class=\"it-fail\"" + d + ">F</span>";
	if(r == "SUSPICIOUS")      return "<span class=\"it-fail\"" + d + ">S</span>";
    if(r == "NOCAPTURE") return "<span class=\"it-nc\"" + d + ">NC</span>";
    return "N/A";
}

static vector<InjectionCacheEntry> read_cache(const path &cache_path) {
    vector<InjectionCacheEntry> entries;
    if(!exists(cache_path)) return entries;
    ifstream ifs(cache_path);
    string line;
    while(getline(ifs, line)) {
        if(line.empty()) continue;
        const auto sep = line.find('\t');
        if(sep == string::npos) continue;
        auto j = json::parse(line.substr(sep + 1), nullptr, false);
        if(j.is_discarded() || j.contains("err_msg")) continue;
        InjectionCacheEntry e;
        e.tx_mac    = j.value("tx_mac", "?");
        e.rx_mac    = j.value("rx_mac", "?");
        e.driver    = j.value("driver", "?");
        e.rx_driver = j.value("rx_driver", "");
        if(j.contains("tests") && j.at("tests").is_object()) {
	        for(const auto &[name, val] : j.at("tests").items()) {
		        e.tests[name] = {val.value("result", "?"), val.value("detail", "")};
	        }
        }
        entries.push_back(std::move(e));
    }
    return entries;
}

static vector<string> collect_test_names(const vector<InjectionCacheEntry> &entries) {
    set<string> seen;
    vector<string> names;
    for(const auto &e : entries) {
	    for(const auto &name: e.tests | views::keys) {
	    	if(seen.insert(name).second) names.push_back(name);
	    }
    }
    return names;
}

void generate_injection_overview(const path &output_dir, const path &data_dir) {
    const path cache_path = data_dir / "cache" / "two_iface" / "two_iface_inject" / "cache.txt";
    const path page_dir   = output_dir / "attacks" / "two_iface" / "injection";
    create_public_dirs(page_dir);

    HtmlGuard f(page_dir);

    f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Injection Test Cache</title>
    <link rel="stylesheet" href="../../../style.css">
</head>
<body>
    <a href="../../../index.html" class="back-link"><= Overview</a>
    <h1>Injection Test - results from cache </h1>
    <div class="card">
		<p><b>Sources:</b>
		<ul>
			<li>https://github.com/vanhoefm/wifi-injection</li>
			<li>https://papers.mathyvanhoef.com/wisec2023-wifi-injection.pdf</li>
		</ul>
		</p>
		<p><b>Tests:</b>
		valid - correct mac, spoofed - changed mac
		<ul>
			<li>injection_fields_(spoofed/valid) - normal monitor injection </li>
			<li>injection_more_fragments_(spoofed/valid) - check if client dont ignore frames with more fragments flag</li>
			<li>injection_order_(spoofed/valid) - check if order of injected frames is correct (not changed from user space send)</li>
			<li>injection_fields_retrans - check if frames are retransmitted</li>
			<li>test_injection_txack - check if probe response and ack is captured with transceiver</li>
		</ul>
		</p>
    </div>
    <div class="card">
	<p>Frame injection capability results cached per (transceiver, receiver) hardware pair.</p>
	<p><b>P</b> = PASSED <b>F</b> = FAIL <b>NC</b> = no capture <b>S</b> = suspicious <b>N/A</b> = not tested</p>
)html";

    auto entries    = read_cache(cache_path);

	ranges::sort(entries, [](const InjectionCacheEntry &a, const InjectionCacheEntry &b) {
	return tie(a.tx_mac, a.rx_mac, a.driver, a.rx_driver) < tie(b.tx_mac, b.rx_mac, b.driver, b.rx_driver); });

    const auto test_names = collect_test_names(entries);

    if(entries.empty()) {
        f << "<p>No cached results found.</p>";
    } else {
        HtmlPathTable table(f, entries);
        table.add_column("TX MAC",    &InjectionCacheEntry::tx_mac);
        table.add_column("RX MAC",    &InjectionCacheEntry::rx_mac);
        table.add_column("TX Driver", &InjectionCacheEntry::driver);
        table.add_column("RX Driver", &InjectionCacheEntry::rx_driver);
        for(const auto &name : test_names) {
            table.add_rotated_column(name, [name](const InjectionCacheEntry &e) -> string {
                const auto it = e.tests.find(name);
                return it != e.tests.end()
                    ? result_cell(it->second.first, it->second.second)
                    : result_cell("-");
            });
        }
        table.render();
    }
    f << "</div></body></html>";
}

}
