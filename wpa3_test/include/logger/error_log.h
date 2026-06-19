#pragma once
#include <format>
#include <source_location>
#include <stacktrace>
#include <stdexcept>
#include <string>
#include "log.h"

namespace wpa3_tester{
class tester_error: public std::runtime_error, public std::nested_exception{
public:
	explicit tester_error(const std::string &msg, const std::source_location loc = std::source_location::current())
	: std::runtime_error(msg), location_(loc){}

	[[nodiscard]] const std::source_location &where() const noexcept{ return location_; }
private:
	std::source_location location_{};
};

// Wrapper for std::format-style ({}) error messages with source location capture.
// Usage: throw scan_err(fmtloc{"failed: {}"}, path);
struct fmtloc{
	std::string_view fmt;
	std::source_location loc;

	explicit fmtloc(const std::string_view fmt, const std::source_location loc = std::source_location::current())
	: fmt(fmt), loc(loc){}
};

template<LogLevel Level>
class typed_error: public tester_error{
	template<typename...Args>
	static std::string fmt_msg(std::string_view fmt, Args &&...args){
		auto cleaned = std::make_tuple(clean_arg(std::forward<Args>(args))...);
		return std::apply([&fmt](auto &...a){
			return std::vformat(fmt, std::make_format_args(a...));
		}, cleaned);
	}
public:
	explicit typed_error(const std::string &msg, const std::source_location loc = std::source_location::current())
	: tester_error(msg, loc){
		log(Level, "{}", std::runtime_error::what());
	}

	// Implicit conversion from string literal allows: throw some_err("format {}", arg);
	struct fmtloc_implicit{
		const char *fmt;
		std::source_location loc;

		fmtloc_implicit( // non-explicit: enables implicit construction from string literal
			const char *fmt, const std::source_location loc = std::source_location::current()
		): fmt(fmt), loc(loc){}
	};

	template<typename...Args>
	explicit typed_error(fmtloc_implicit f, Args &&...args)
	: tester_error(fmt_msg(f.fmt, std::forward<Args>(args)...), f.loc){
		log(Level, "{}", std::runtime_error::what());
	}

	template<typename...Args>
	explicit typed_error(const fmtloc f, Args &&...args)
	: tester_error(fmt_msg(f.fmt, std::forward<Args>(args)...), f.loc){
		log(Level, "{}", std::runtime_error::what());
	}
};

using config_err = typed_error<LogLevel::CRITICAL>;
using compile_err = typed_error<LogLevel::CRITICAL>;
using install_err = typed_error<LogLevel::CRITICAL>;

using req_err = typed_error<LogLevel::CRITICAL>;
using run_err = typed_error<LogLevel::CRITICAL>;
using setup_err = typed_error<LogLevel::CRITICAL>;
using scan_err = typed_error<LogLevel::CRITICAL>;
using stats_err = typed_error<LogLevel::ERROR>;

using not_implemented_err = typed_error<LogLevel::CRITICAL>;
using timeout_err = typed_error<LogLevel::ERROR>;

using ex_conn_err = typed_error<LogLevel::CRITICAL>;
}
