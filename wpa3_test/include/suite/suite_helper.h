#pragma once
#include <filesystem>
#include <memory>
#include <vector>
#include <boost/pfr.hpp>

#include "default.h"
#include "config/RunStatus.h"
#include "overview/html_guard.h"

namespace wpa3_tester::suite::helper{

std::unique_ptr<RunStatus> load_test_rs(const std::filesystem::path &test_folder);

// returns test subdirectories inside suite_dir
std::vector<std::filesystem::path> get_suite_test_folders(const std::filesystem::path &suite_dir);

template<typename ParseFn>
auto collect_entries_nested(const std::filesystem::path &run_dir, ParseFn parse_fn){
	using E = decltype(parse_fn(std::declval<const std::filesystem::path&>()));
	std::vector<E> entries;
	for(const auto &src_dir: std::filesystem::directory_iterator(run_dir)){
		if(!src_dir.is_directory()) continue;
		for(const auto &entry: std::filesystem::directory_iterator(src_dir.path())){
			if(!entry.is_directory()) continue;
			if(!std::filesystem::exists(entry.path() / TEST_CONFIG_NAME)) continue;
			entries.push_back(parse_fn(entry.path()));
		}
	}
	return entries;
}

// parsing with Entry::parse (some results needs test_folder inf)
template<typename Entry>
std::vector<Entry> get_results_default(const std::filesystem::path &run_dir){
	return collect_entries_nested(run_dir, Entry::parse);
}

// card with table
template <typename T>
concept HasCollectResults = requires(const std::filesystem::path& p) {
	{ T::collect_results(p) };
};

template <typename Entry>
void div_card(overview::HtmlGuard &f, const std::string &title, const std::filesystem::path &suite_data_dir,
	const std::function<void(overview::HtmlGuard&, const std::vector<Entry>&)> &render_func)
{
	if(!std::filesystem::exists(suite_data_dir)){
		//TODO
		return;
	}
	f   << "    <div class=\"card\" style=\"overflow-x: auto;\">\n"
		<< "        <h2>" << title << "</h2>\n";

	//preferred collect_results, if not
	auto entries = [suite_data_dir]() {
		if constexpr (HasCollectResults<Entry>) {
			return Entry::collect_results(suite_data_dir);
		} else {
			return helper::get_results_default<Entry>(suite_data_dir);
		}
	}();

	render_func(f, entries);
	f << "</div>";
}

}
