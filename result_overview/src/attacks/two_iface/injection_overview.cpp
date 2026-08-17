#include "attacks/two_iface/injection_overview.h"
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <nlohmann/json.hpp>
#include "overview/html_guard.h"
#include "overview/html_utils.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using nlohmann::json;

struct InjectionCacheEntry {
    string tx_mac;
    string rx_mac;
    string driver;
    string rx_driver;
    map<string, string> tests; // test_name -> reuslt ("PASSED"/"FAIL"/"NOCAPTURE")
};

static string result_cell(const string &r) {
    if(r == "PASSED")    return "<span class=\"it-pass\">P</span>";
    if(r == "FAIL")      return "<span class=\"it-fail\">F</span>";
    if(r == "NOCAPTURE") return "<span class=\"it-nc\">NC</span>";
    return "-";
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
        if(j.contains("tests") && j.at("tests").is_object())
            for(const auto &[name, val] : j.at("tests").items())
                e.tests[name] = val.value("result", "?");
        entries.push_back(std::move(e));
    }
    return entries;
}

static vector<string> collect_test_names(const vector<InjectionCacheEntry> &entries) {
    set<string> seen;
    vector<string> names;
    for(const auto &e : entries)
        for(const auto &[name, _] : e.tests)
            if(seen.insert(name).second) names.push_back(name);
    return names;
}

void generate_injection_overview(const path &output_dir, const path &data_dir) {
    const path cache_path = data_dir / "cache" / "two_iface" / "two_iface_inject" / "cache.txt";
    const path page_dir   = output_dir / "attacks" / "two_iface" / "injection";
    create_public_dirs(page_dir);

    HtmlGuard f(page_dir);
    if(!f) return;

    f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Injection Test Cache</title>
    <link rel="stylesheet" href="../../../style.css">
</head>
<body>
    <a href="../../../index.html" class="back-link">&lt;- Overview</a>
    <h1>Injection Test — Cached Results</h1>
    <div class="card">
        <p>Frame injection capability results cached per (transceiver, receiver) hardware pair.</p>
        <p><b>P</b> = PASSED &nbsp; <b>F</b> = FAIL &nbsp; <b>NC</b> = no capture &nbsp; <b>-</b> = not tested</p>
    </div>
    <div class="card">
)html";

    const auto entries    = read_cache(cache_path);
    const auto test_names = collect_test_names(entries);

    if(entries.empty()) {
        f << string("<p>No cached results found.</p>");
    } else {
        HtmlPathTable table(f, entries);
        table.add_column("TX MAC",    &InjectionCacheEntry::tx_mac);
        table.add_column("RX MAC",    &InjectionCacheEntry::rx_mac);
        table.add_column("TX Driver", &InjectionCacheEntry::driver);
        table.add_column("RX Driver", &InjectionCacheEntry::rx_driver);
        for(const auto &name : test_names) {
            table.add_rotated_column(name, [name](const InjectionCacheEntry &e) -> string {
                const auto it = e.tests.find(name);
                return result_cell(it != e.tests.end() ? it->second : "-");
            });
        }
        table.render();
    }

    f << string("    </div>\n</body>\n</html>\n");
}

}
