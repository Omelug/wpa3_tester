#pragma once
#include <filesystem>
#include <string>
namespace wpa3_tester::overview { struct HtmlGuard; }

namespace wpa3_tester::visual::sae_dos {

struct SaeDosFolderEntry {
	std::string test_folder;
	std::string name;
	std::filesystem::path ap_res_png;

	static SaeDosFolderEntry parse(const std::filesystem::path &test_folder);
	static void render_table(overview::HtmlGuard &f,
							const std::string &title, const std::filesystem::path &suite_data_dir, const std::filesystem::path &page_dir
	);
};

}
