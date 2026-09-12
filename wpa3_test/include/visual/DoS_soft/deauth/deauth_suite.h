#pragma once
#include "config/RunSuiteStatus.h"
#include "overview/described.h"
#include "overview/html_guard.h"
#include <filesystem>
#include <optional>
#include <string>

namespace wpa3_tester::visual::deauth_suite {

struct DeauthTestEntry {
    std::string test_name;
    std::string ap_mac;
    std::string ap_source;
    std::string ap_driver;

    std::string client_mac;
    std::string client_source;
    std::optional<std::string> client_driver;
    std::string client_version;

    std::string attacker_mac;
    std::string attacker_driver;

    // result fields — names match result.json keys
    described_bool client_disconnected;
    std::optional<bool> ap_disconnected;
    described_str client_mfp;
    described_str ap_WPA_support;
    described_str client_WPA_support;
    described_str conn_WPA_version;

    static DeauthTestEntry parse(const std::filesystem::path &test_folder);
    static std::vector<DeauthTestEntry> collect_results(const std::filesystem::path &test_data_dir);
    static void render_table(overview::HtmlGuard &f, const std::string &title,
                             const std::filesystem::path &suite_data_dir,
                             const std::filesystem::path &page_dir,
                             const std::string &t_name);
    static void generate_report(const RunSuiteStatus &rss);
};

}
