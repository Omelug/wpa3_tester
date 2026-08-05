#pragma once
#include <filesystem>

namespace wpa3_tester::overview {
struct HtmlGuard;
using RenderFunc = std::function<void(
	HtmlGuard&,
	const std::string&,
	const std::filesystem::path&,
	const std::filesystem::path&
)>;

template<typename Entry>
RenderFunc make_renderer() {
	return [](HtmlGuard &f, const std::string &module,
			  const std::filesystem::path &suite_data_dir,
			  const std::filesystem::path &page_dir) {
		Entry::render_table(f, module, suite_data_dir, page_dir);
	};
}

void generate_targets(const std::filesystem::path &output_dir, const std::filesystem::path &data_dir);
}
