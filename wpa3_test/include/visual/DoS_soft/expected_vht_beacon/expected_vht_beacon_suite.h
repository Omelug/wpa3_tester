#pragma once
#include "config/RunSuiteStatus.h"
#include "overview/html_guard.h"
#include <filesystem>
#include <optional>
#include <string>

namespace wpa3_tester::visual::expected_vht_beacon_suite {

struct ExpVhtTestEntry {
    // display fields — populated in parse(), not from result.json
    std::string name;
    std::string ap_mac;
    std::string ap_source;
    std::string client_mac;
    std::string client_source;
    std::string attacker_mac;
    std::string attacker_driver;
    std::string rogue_ap_mac;
    std::string rogue_ap_driver;

    // result fields — names must match result.json keys (auto-loaded by load_result_default)
    int disconnect_count = 0;
    bool dmesg_change_mode_disconnect = false;
    bool ap_disconnected = false;
    std::optional<bool> rogue_ap_connected;
    std::optional<bool> cracked;

    static ExpVhtTestEntry parse(const std::filesystem::path &test_folder);
    static void render_table(overview::HtmlGuard &f, const std::string &title,
                             const std::filesystem::path &suite_data_dir,
                             const std::filesystem::path &page_dir,
                             const std::string &t_name);
    static void generate_report(RunSuiteStatus &rss);
};

}
