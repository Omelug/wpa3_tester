#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace wpa3_tester::overview { struct HtmlGuard; }

namespace wpa3_tester::suite::sae_dos {

struct SaeDosFolderEntry {
    std::string name;
    std::filesystem::path ap_res_png;

    static SaeDosFolderEntry parse(const std::filesystem::path &test_folder);
    static void render_table(overview::HtmlGuard &f,
                             const std::vector<std::filesystem::path> &folders,
                             const std::filesystem::path &page_dir);
};

}
