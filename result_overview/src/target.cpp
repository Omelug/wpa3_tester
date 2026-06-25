#include "target.h"

#include <filesystem>
#include <map>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>

#include "html_guard.h"
#include "system/utils.h"
#include "suite/scan/ap_info_wpa3_filler.h"
#include "suite/DoS_soft/bl0ck/bl0ck_test_suites.h"
#include "suite/DoS_soft/channel_switch/channel_switch_rogueAP.h"
#include "suite/Enterprise/invalid_curve/invalid_curve_filler.h"
#include "suite/Enterprise/reflection_attack/reflection_attack_filler.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;

static const map<string, string> k_attack_page = {
    {"bl0ck",            "../../attacks/dos_soft/bl0ck/index.html"},
    {"channel_switch",   "../../attacks/dos_soft/channel_switch/index.html"},
    {"malformed_eapol1", "../../attacks/dos_soft/malformed_eapol1/index.html"},
};

static const map<string, string> k_attack_title = {
    {"ap_info",           "AP Info (Scanner)"},
    {"bl0ck",             "Bl0ck — Block ACK DoS"},
    {"channel_switch",    "Channel Switch (CSA) DoS"},
    {"malformed_eapol1",  "Malformed EAPOL-1 DoS"},
    {"invalid_curve",     "Invalid Curve Attack (EAP-PWD)"},
    {"reflection_attack", "Reflection Attack (EAP-PWD)"},
};

static string read_attacker_module(const path &test_folder) {
    const auto cfg = test_folder / "test_config.yaml";
    if (!exists(cfg)) return "";
    try {
        const auto node = YAML::LoadFile(cfg.string());
        if (node["attacker_module"])
            return node["attacker_module"].as<string>();
    } catch (...) {}
    return "";
}

// last_run/{attack_dir}/{test_dir}/test_config.yaml
static vector<path> collect_test_folders(const path &run_dir) {
    vector<path> result;
    if (!is_directory(run_dir)) return result;
    for (const auto &attack_dir : directory_iterator(run_dir)) {
        if (!attack_dir.is_directory()) continue;
        for (const auto &test_dir : directory_iterator(attack_dir.path())) {
            if (!test_dir.is_directory()) continue;
            if (exists(test_dir.path() / "test_config.yaml"))
                result.push_back(test_dir.path());
        }
    }
    return result;
}

static void emit_section_header(HtmlGuard &f, const string &module) {
    const auto title_it = k_attack_title.find(module);
    const auto title = (title_it != k_attack_title.end()) ? title_it->second : module;
    const auto page_it = k_attack_page.find(module);

    f << "    <div class=\"card\" style=\"overflow-x: auto;\">\n"
      << "        <h2>";
    if (page_it != k_attack_page.end())
        f << "<a href=\"" << page_it->second << "\">" << title << "</a>";
    else
        f << title;
    f << "</h2>\n";
}

static string test_name_cell(const path &test_folder, const string &name, const path &page_dir) {
    const auto report = test_folder / "report.md";
    if (!exists(report)) return name;
    return "<a href=\"" + report.lexically_relative(page_dir).string() + "\">" + name + "</a>";
}

static void render_ap_info(HtmlGuard &f, const vector<path> &folders) {
    using suite::ap_info_wpa3_filler::ApInfoWpa3TestEntry;
    f << "        <table class=\"aggregate\">\n"
      << "            <thead><tr>"
      << "<th>Test</th><th>MAC</th><th>SSID</th><th>MFP</th><th>AKM</th><th>ACM triggered</th>"
      << "</tr></thead>\n            <tbody>\n";
    for (const auto &p : folders) {
        const auto e = ApInfoWpa3TestEntry::parse(p);
        f << "                <tr>\n"
          << "                    <td>" << e.test_name << "</td>\n"
          << "                    <td>" << e.mac << "</td>\n"
          << "                    <td>" << e.ssid << "</td>\n"
          << "                    <td>" << e.mfp << "</td>\n"
          << "                    <td>" << e.akm << "</td>\n"
          << "                    <td>" << e.acm_triggered << "</td>\n"
          << "                </tr>\n";
    }
    f << "            </tbody>\n        </table>\n";
}

static void render_bl0ck(HtmlGuard &f, const vector<path> &folders, const path &page_dir) {
    using suite::bl0ck_test_suites::Bl0ckTestEntry;
    f << "        <table class=\"aggregate\">\n"
      << "            <thead><tr>"
      << "<th>Test</th><th>AP MAC (source)</th><th>Client MAC (source)</th>"
      << "<th>Attacker (driver)</th><th>Variant</th><th>Disconnected?</th>"
      << "</tr></thead>\n            <tbody>\n";
    for (const auto &p : folders) {
        const auto e = Bl0ckTestEntry::parse(p);
        f << "                <tr>\n"
          << "                    <td>" << test_name_cell(p, e.name, page_dir) << "</td>\n"
          << "                    <td>" << device(e.ap_mac, page_dir) << " (" << e.ap_source << ")</td>\n"
          << "                    <td>" << device(e.client_mac, page_dir) << " (" << e.client_source << ")</td>\n"
          << "                    <td>" << device(e.attacker_mac, page_dir) << " (" << e.attacker_driver << ")</td>\n"
          << "                    <td>" << e.attack_variant << "</td>\n"
          << "                    <td>" << (e.disconnect_count > 0) << "</td>\n"
          << "                </tr>\n";
    }
    f << "            </tbody>\n        </table>\n";
}

static void render_channel_switch(HtmlGuard &f, const vector<path> &folders, const path &page_dir) {
    f << "        <table class=\"aggregate\">\n"
      << "            <thead><tr>"
      << "<th>Test</th><th>AP MAC (source)</th><th>Client MAC (source)</th>"
      << "<th>Attacker (driver)</th><th>Disconnected?</th><th>Rogue AP?</th><th>Client MFP</th>"
      << "</tr></thead>\n            <tbody>\n";
    for (const auto &p : folders) {
        const auto e = suite::channel_switch_rogueAP::parse_test_folder(p);
        f << "                <tr>\n"
          << "                    <td>" << test_name_cell(p, e.name, page_dir) << "</td>\n"
          << "                    <td>" << device(e.ap_mac, page_dir) << " (" << e.ap_source << ")</td>\n"
          << "                    <td>" << device(e.client_mac, page_dir) << " (" << e.client_source << ")</td>\n"
          << "                    <td>" << device(e.attacker_mac, page_dir) << " (" << e.attacker_driver << ")</td>\n"
          << "                    <td>" << e.disconnected << "</td>\n"
          << "                    <td>" << e.rogue_ap_connected << "</td>\n"
          << "                    <td>" << e.client_mfp << "</td>\n"
          << "                </tr>\n";
    }
    f << "            </tbody>\n        </table>\n";
}

static void render_invalid_curve(HtmlGuard &f, const vector<path> &folders) {
    using suite::invalid_curve_filler::InvalidCurveTestEntry;
    f << "        <table class=\"aggregate\">\n"
      << "            <thead><tr>"
      << "<th>Test</th><th>AP Driver</th><th>Attacker Driver</th><th>Passed?</th>"
      << "</tr></thead>\n            <tbody>\n";
    for (const auto &p : folders) {
        const auto e = InvalidCurveTestEntry::parse(p);
        f << "                <tr>\n"
          << "                    <td>" << e.test_name << "</td>\n"
          << "                    <td>" << e.ap_driver << "</td>\n"
          << "                    <td>" << e.attacker_driver << "</td>\n"
          << "                    <td>" << e.passed << "</td>\n"
          << "                </tr>\n";
    }
    f << "            </tbody>\n        </table>\n";
}

static void render_reflection_attack(HtmlGuard &f, const vector<path> &folders) {
    using suite::reflection_attack_filler::ReflectionAttackTestEntry;
    f << "        <table class=\"aggregate\">\n"
      << "            <thead><tr>"
      << "<th>Test</th><th>AP Driver</th><th>Attacker Driver</th><th>Passed?</th>"
      << "</tr></thead>\n            <tbody>\n";
    for (const auto &p : folders) {
        const auto e = ReflectionAttackTestEntry::parse(p);
        f << "                <tr>\n"
          << "                    <td>" << e.test_name << "</td>\n"
          << "                    <td>" << e.ap_driver << "</td>\n"
          << "                    <td>" << e.attacker_driver << "</td>\n"
          << "                    <td>" << e.passed << "</td>\n"
          << "                </tr>\n";
    }
    f << "            </tbody>\n        </table>\n";
}

static void render_attack_section(HtmlGuard &f, const string &module,
                                  const vector<path> &folders, const path &page_dir) {
    emit_section_header(f, module);

    if      (module == "ap_info")           render_ap_info(f, folders);
    else if (module == "bl0ck")             render_bl0ck(f, folders, page_dir);
    else if (module == "channel_switch")    render_channel_switch(f, folders, page_dir);
    else if (module == "invalid_curve")     render_invalid_curve(f, folders);
    else if (module == "reflection_attack") render_reflection_attack(f, folders);
    else {
        f << "        <p>No parser for <code>" << module << "</code>.</p>\n";
    }

    f << "    </div>\n";
}

static void generate_target_page(const path &output_dir,
                                  const string &target_name,
                                  const path &target_data_dir) {
    const path page_dir = output_dir / "target" / target_name;
    create_public_dirs(page_dir);

    HtmlGuard f(page_dir);
    if (!f) return;

    f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>)html" << target_name << R"html( — WPA3 Target Report</title>
    <link rel="stylesheet" href="../../style.css">
    <script src="../../table_aggregate.js"></script>
</head>
<body>
    <a href="../../index.html" class="back-link">← Overview</a>
    <h1>)html" << target_name << R"html(</h1>
)html";

    const path suites_dir = target_data_dir / "suite";
    if (!is_directory(suites_dir)) {
        f << "    <div class=\"card\"><p>No suites found.</p></div>\n"
          << "</body>\n</html>\n";
        return;
    }

    bool any = false;
    for (const auto &suite_entry : directory_iterator(suites_dir)) {
        if (!suite_entry.is_directory()) continue;
        const string suite_name = suite_entry.path().filename().string();
        const auto test_folders = collect_test_folders(suite_entry.path());
        if (test_folders.empty()) continue;
        any = true;

        f << "    <div class=\"card\">\n"
          << "        <h2>Suite: " << suite_name << "</h2>\n"
          << "    </div>\n";

        map<string, vector<path>> groups;
        for (const auto &tf : test_folders) {
            const auto mod = read_attacker_module(tf);
            if (!mod.empty())
                groups[mod].push_back(tf);
        }

        for (const auto &[mod, folders] : groups)
            render_attack_section(f, mod, folders, page_dir);
    }

    if (!any)
        f << "    <div class=\"card\"><p>No test results found.</p></div>\n";

    f << "</body>\n</html>\n";
}

static void generate_target_index(const path &output_dir, const vector<string> &targets) {
    const path idx_dir = output_dir / "target";
    create_public_dirs(idx_dir);

    HtmlGuard f(idx_dir);
    if (!f) return;

    f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Targets — WPA3 Tester</title>
    <link rel="stylesheet" href="../style.css">
</head>
<body>
    <a href="../index.html" class="back-link">← Overview</a>
    <h1>Targets</h1>
    <div class="card">
        <ul>
)html";
    for (const auto &t : targets)
        f << "            <li><a href=\"" << t << "/index.html\">" << t << "</a></li>\n";
    f << "        </ul>\n    </div>\n</body>\n</html>\n";
}

void generate_targets(const path &output_dir, const path &data_dir) {
    const path targets_data = data_dir / "wpa3_suites" / "target";
    if (!is_directory(targets_data)) return;

    vector<string> names;
    for (const auto &entry : directory_iterator(targets_data)) {
        if (!entry.is_directory()) continue;
        const string name = entry.path().filename().string();
        names.push_back(name);
        generate_target_page(output_dir, name, entry.path());
    }

    if (!names.empty())
        generate_target_index(output_dir, names);
}

} // namespace wpa3_tester::overview
