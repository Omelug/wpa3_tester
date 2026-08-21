#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::overview { struct HtmlGuard; }

namespace wpa3_tester::visual::mc_mitm_filler {

struct McMitmEntry {
    std::string test_name;
    std::string ap_mac;
    std::string client_mac;
    std::string rogue_client_driver;
    std::string rogue_ap_driver;
    std::string ssid;
    std::optional<bool> mitm_achieved;
    std::filesystem::path rel_path;

    static McMitmEntry parse(const std::filesystem::path &test_folder);
    static std::vector<McMitmEntry> collect_results(const std::filesystem::path &suite_data_dir);
    static void render_table(overview::HtmlGuard &f,
                             const std::string &title,
                             const std::filesystem::path &suite_data_dir,
                             const std::filesystem::path &page_dir);
    static void generate_report(RunSuiteStatus &rss);
};

}
