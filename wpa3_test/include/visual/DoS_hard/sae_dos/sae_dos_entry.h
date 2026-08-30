#pragma once
#include <filesystem>
#include <string>
#include <vector>
namespace wpa3_tester::overview { struct HtmlGuard; }

namespace wpa3_tester::visual::sae_dos {

struct SaeDosFolderEntry {
	std::string test_folder;
	std::string name;
	std::filesystem::path ap_res_png;

	static SaeDosFolderEntry parse(const std::filesystem::path &test_folder);
	static std::vector<SaeDosFolderEntry> collect_results(const std::filesystem::path &suite_data_dir,
														  const std::string &module_filter = "");
	static void render_table(overview::HtmlGuard &f, const std::string &module,
							 const std::filesystem::path &suite_data_dir,
							 const std::filesystem::path &page_dir,
							 const std::string &t_name);
};

}
