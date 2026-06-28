#include "target.h"

#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>

#include "overview/html_guard.h"
#include "system/utils.h"
#include "suite/scan/ap_info_wpa3_filler.h"
#include "suite/DoS_soft/bl0ck/bl0ck_test_suites.h"
#include "suite/DoS_soft/channel_switch/channel_switch_rogueAP.h"
#include "suite/Enterprise/invalid_curve/invalid_curve_filler.h"
#include "suite/Enterprise/reflection_attack/reflection_attack_filler.h"
#include "suite/DoS_hard/sae_dos/sae_dos_entry.h"

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
    {"sae_dos_wrapper",   "SAE DoS (generic variants)"},
    {"cookie_guzzler",    "Cookie Guzzler DoS"},
    {"memory_omnivore",   "Memory Omnivore DoS"},
    {"pmk_gobbler",       "PMK Gobbler DoS"},
};

static const set<string> k_sae_dos_modules = {
    "sae_dos_wrapper", "cookie_guzzler", "memory_omnivore", "pmk_gobbler",
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

static void render_attack_section(HtmlGuard &f, const string &module,
                                  const vector<path> &folders, const path &page_dir) {
    using namespace suite;
    emit_section_header(f, module);

    if      (module == "ap_info")           ap_info_wpa3_filler::ApInfoWpa3TestEntry::render_table(f, folders, page_dir);
    else if (module == "bl0ck")             bl0ck_test_suites::Bl0ckTestEntry::render_table(f, folders, page_dir);
    else if (module == "channel_switch")    channel_switch_rogueAP::render_table(f, folders, page_dir);
    else if (module == "invalid_curve")     invalid_curve_filler::InvalidCurveTestEntry::render_table(f, folders, page_dir);
    else if (module == "reflection_attack") reflection_attack_filler::ReflectionAttackTestEntry::render_table(f, folders, page_dir);
    else if (k_sae_dos_modules.contains(module)) sae_dos::SaeDosFolderEntry::render_table(f, folders, page_dir);
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
