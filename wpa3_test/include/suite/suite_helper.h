#pragma once
#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>
#include <boost/pfr.hpp>

#include "default.h"
#include "config/RunStatus.h"

namespace wpa3_tester::suite::helper{

std::unique_ptr<RunStatus> load_test_rs(const std::filesystem::path &test_folder);

// open report.md for write
std::ofstream open_report(const std::filesystem::path &report_path);

// close report, fix permissions, log "Report written"
void finalize_report(std::ofstream &report, const std::filesystem::path &run_dir);

// returns test subdirectories inside suite_dir
std::vector<std::filesystem::path> get_suite_test_folders(const std::filesystem::path &suite_dir);

// RAII report guard: opens report.md, exposes operator<<, finalizes on destruction
struct ReportGuard {
	explicit ReportGuard(const std::filesystem::path &run_dir)
		: stream_(open_report(run_dir)), run_dir_(run_dir) {}
	~ReportGuard(){ if(stream_.is_open()) finalize_report(stream_, run_dir_); }
	ReportGuard(const ReportGuard &) = delete;
	ReportGuard &operator=(const ReportGuard &) = delete;

	explicit operator bool() const { return stream_.is_open(); }

	template<typename T>
	std::ostream &operator<<(T &&val){ return stream_ << std::forward<T>(val); }

private:
	std::ofstream stream_;
	std::filesystem::path run_dir_;
};

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

template<typename Entry>
std::vector<Entry> get_results_default(const std::filesystem::path &run_dir){
	return collect_entries_nested(run_dir, Entry::parse);
}
}
