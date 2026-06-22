#pragma once
#include <iosfwd>

#include "config/RunStatus.h"
#include <optional>

// functions here don't check if stream is open, have to be checked before
namespace wpa3_tester::report{

// open report.md for write
std::ofstream open_report(const std::filesystem::path &report_path);

// close report, fix permissions, log "Report written"
void finalize_report(std::ofstream &report, const std::filesystem::path &run_dir);

// RAII report guard: opens report.md, exposes operator<<, finalizes on destruction
struct ReportGuard {
	explicit ReportGuard(const std::filesystem::path &run_dir)
		: stream_(open_report(run_dir)), run_dir_(run_dir) {}
	~ReportGuard(){ if(stream_.is_open()) finalize_report(stream_, run_dir_); }
	ReportGuard(const ReportGuard &) = delete;
	ReportGuard &operator=(const ReportGuard &) = delete;

	explicit operator bool() const { return stream_.is_open(); }
    ReportGuard &operator<<(const std::filesystem::path &p){
	    const auto rel = p.is_absolute() ? p.lexically_relative(run_dir_) : p;
	    stream_ << rel.string(); return *this;
	}

    ReportGuard &operator<<(const bool val){ stream_ << (val ? "yes" : "no"); return *this; }
    ReportGuard &operator<<(const std::optional<bool> val){ stream_ << (val ? (*val ? "yes" : "no") : "N/A"); return *this; }

	ReportGuard &operator<<(const std::string &val){ if(val.empty()) stream_ << '?'; else stream_ << val; return *this; }
	ReportGuard &operator<<(std::string &&val){ if(val.empty()) stream_ << '?'; else stream_ << val; return *this; }

	template<typename T>
	requires (!std::same_as<std::remove_cvref_t<T>, bool> &&
	          !std::same_as<std::remove_cvref_t<T>, std::optional<bool>> &&
	          !std::same_as<std::remove_cvref_t<T>, std::string> &&
	          !std::same_as<std::remove_cvref_t<T>, std::filesystem::path>)
	ReportGuard &operator<<(T &&val){ stream_ << std::forward<T>(val); return *this; }

private:
	std::ofstream stream_;
	std::filesystem::path run_dir_;
};

void attack_config_table(ReportGuard &report, const RunStatus &rs);
void attack_mapping_table(ReportGuard &report, const RunStatus &rs);

std::string device(Tins::HWAddress<6> mac);
std::string yn(BK k);
}
