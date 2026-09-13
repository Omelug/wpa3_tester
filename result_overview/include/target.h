#pragma once
#include <filesystem>

namespace wpa3_tester::overview {
struct HtmlGuard;
using RenderFunc = std::function<void(HtmlGuard &, const std::string &, const std::filesystem::path &,
		const std::filesystem::path &, const std::string &t_name)>;

template<typename Entry>
RenderFunc make_renderer() {
	return [](HtmlGuard &f,
				   const std::string &title,
				   const std::filesystem::path &suite_data_dir,
				   const std::filesystem::path &page_dir,
				   const std::string &module) { Entry::render_table(f, title, suite_data_dir, page_dir, module); };
}

void generate_targets(const std::filesystem::path &output_dir, const std::filesystem::path &data_dir);
}
