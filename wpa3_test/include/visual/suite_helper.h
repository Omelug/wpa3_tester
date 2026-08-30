#pragma once
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>
#include <boost/pfr.hpp>

#include "default.h"
#include "config/RunStatus.h"
#include "overview/html_guard.h"

namespace wpa3_tester::visual::helper{

std::unique_ptr<RunStatus> load_test_rs(const std::filesystem::path &test_folder);

// returns test subdirectories inside suite_dir
std::vector<std::filesystem::path> get_suite_test_folders(const std::filesystem::path &suite_dir);

// Read attacker_module: value from test_config.yaml without a YAML library
inline std::string read_attacker_module_field(const std::filesystem::path &test_dir){
	std::ifstream f(test_dir / TEST_CONFIG_NAME);
	std::string line;
	while(std::getline(f, line)){
		if(line.rfind("attacker_module:", 0) == 0){
			auto val = line.substr(line.find(':') + 1);
			const auto s = val.find_first_not_of(" \t");
			if(s != std::string::npos) val = val.substr(s);
			const auto e = val.find_last_not_of(" \t\r\n");
			return e != std::string::npos ? val.substr(0, e + 1) : val;
		}
	}
	return "";
}

template<typename ParseFn>
auto collect_entries_nested(const std::filesystem::path &run_dir, ParseFn parse_fn,
							const std::string &module_filter = ""){
	using E = decltype(parse_fn(std::declval<const std::filesystem::path&>()));
	std::vector<E> entries;
	for(const auto &src_dir: std::filesystem::directory_iterator(run_dir)){
		if(!src_dir.is_directory()) continue;
		for(const auto &entry: std::filesystem::directory_iterator(src_dir.path())){
			if(!entry.is_directory()) continue;
			if(!std::filesystem::exists(entry.path() / TEST_CONFIG_NAME)) continue;
			if(!module_filter.empty() && read_attacker_module_field(entry.path()) != module_filter) continue;
			entries.push_back(parse_fn(entry.path()));
		}
	}
	return entries;
}

// parsing with Entry::parse (some results needs test_folder inf)
template<typename Entry>
std::vector<Entry> get_results_default(const std::filesystem::path &run_dir,
									   const std::string &module_filter = ""){
	return collect_entries_nested(run_dir, Entry::parse, module_filter);
}

// card with table
template <typename T>
concept HasCollectResultsFiltered = requires(const std::filesystem::path& p, const std::string& s) {
	{ T::collect_results(p, s) };
};

template <typename T>
concept HasCollectResults = requires(const std::filesystem::path& p) {
	{ T::collect_results(p) };
};

template <typename Entry>
void div_card(overview::HtmlGuard &f, const std::string &title, const std::filesystem::path &suite_data_dir,
	const std::function<void(overview::HtmlGuard&, const std::vector<Entry>&)> &render_func,
	const std::string &module_filter = "")
{
	f   << "    <div class=\"card\" style=\"overflow-x: auto;\">\n"
		<< "        <h2>" << title << "</h2>\n";

	if(!std::filesystem::exists(suite_data_dir)){
		render_func(f, {});
		f << "</div>";
		return;
	}

	auto entries = [suite_data_dir, &module_filter]() {
		if constexpr (HasCollectResultsFiltered<Entry>) {
			return Entry::collect_results(suite_data_dir, module_filter);
		} else if constexpr (HasCollectResults<Entry>) {
			return Entry::collect_results(suite_data_dir);
		} else {
			return helper::get_results_default<Entry>(suite_data_dir, module_filter);
		}
	}();

	render_func(f, entries);
	f << "</div>";
}

}
