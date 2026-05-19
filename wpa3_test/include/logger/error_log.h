#pragma once
#include <cstdarg>
#include <source_location>
#include <stacktrace>
#include <stdexcept>
#include <string>
#include "log.h"

namespace wpa3_tester{

class tester_error : public std::runtime_error, public std::nested_exception {
public:
	explicit tester_error(
		const std::string &msg,
		std::source_location loc = std::source_location::current()
	)
	: std::runtime_error(msg)
	, std::nested_exception()
	, location_(loc)
	{}

	template<typename... Args>
	tester_error(LogLevel level, const char *fmt, const std::source_location loc, Args... args)
	: std::runtime_error(vprintf_format(fmt, args...))
	, std::nested_exception()
	, location_(loc)
	{
		log(level, "{}", std::runtime_error::what());
	}

	[[nodiscard]] const std::source_location &where() const noexcept { return location_; }
	static std::string vprintf_format(const char *fmt, ...);
private:
	std::source_location location_{};
};

template<LogLevel Level>
class typed_error : public tester_error {
public:
	explicit typed_error(
		const std::string &msg,
		std::source_location loc = std::source_location::current()
	)
	: tester_error(msg, loc)
	{
		log(Level, "{}", std::runtime_error::what());
	}

	// wrapper struct — zachytí loc na call site před Args...
	struct format_with_location {
		const char *fmt;
		std::source_location loc;

		format_with_location(
			const char *fmt,
			std::source_location loc = std::source_location::current()
		) : fmt(fmt), loc(loc) {}
	};

	template<typename... Args>
	explicit typed_error(format_with_location f, Args... args)
	: tester_error(Level, f.fmt, f.loc, args...) {}
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