#pragma once
#include <chrono>
#include <filesystem>
#include <format>
#include <string>
#include <tins/tins.h>


namespace std{
template<>
struct formatter<filesystem::path>: formatter<string>{
	auto format(const filesystem::path &p, auto &ctx) const{
		return formatter<string>::format(p.string(), ctx);
	}
};

template<size_t n>
struct formatter<Tins::HWAddress<n>>: formatter<string>{
	auto format(const Tins::HWAddress<n> &addr, auto &ctx) const{
		return formatter<string>::format(addr.to_string(), ctx);
	}
};
}

namespace wpa3_tester{
enum class LogLevel{
	DEBUG,
	INFO,
	WARNING,
	ERROR,
	CRITICAL
};

const char *levelToString(LogLevel level);

// Set log file path (optional, nullptr to disable file logging)
void set_log_file(const std::filesystem::path &log_path);
void close_log_file();
void write_log_message(LogLevel level, const std::string &msg);

// enum -> show number; two overloads avoid clangd "auto deduced as different types" error
template<typename T> requires std::is_enum_v<std::decay_t<T>>
auto clean_arg(T &&arg){
	return static_cast<std::underlying_type_t<std::decay_t<T>>>(arg);
}

template<typename T> requires (!std::is_enum_v<std::decay_t<T>>)
std::decay_t<T> clean_arg(T &&arg){
	return std::forward<T>(arg);
}

template<typename... Args>
void log(const LogLevel level, std::format_string<Args...> fmt, Args&&... args) {
	auto cleaned = std::make_tuple(clean_arg(std::forward<Args>(args))...);
	const std::string msg = [&]<size_t... Is>(std::index_sequence<Is...>) {
		return std::vformat(std::string_view(fmt), std::make_format_args(std::get<Is>(cleaned)...));
	}(std::index_sequence_for<Args...>{});
	write_log_message(level, msg);
}

//[[gnu::format(printf, 2, 3)]]
//void log(LogLevel level, const char *fmt, ...);
void log(LogLevel level, const std::string &msg);

using LogTimePoint = std::chrono::time_point<std::chrono::system_clock>;

struct TimeWindow {
	LogTimePoint start_tp{};
	LogTimePoint end_tp{};
	[[nodiscard]] bool contains(const LogTimePoint &t) const { return t >= start_tp && t <= end_tp; }
};

// Returns a nanosecond-precision time_point (system_clock epoch on parse error)
LogTimePoint log_time_to_epoch_ns(const std::string &time_str);
std::string escape_tex(std::string text);
}