#pragma once
#include <chrono>
#include <filesystem>
#include <format>
#include <string>
#include <tins/tins.h>

#include "config/RunStatus.h"

template<>
struct std::formatter<std::filesystem::path>: std::formatter<std::string>{
	auto format(const std::filesystem::path &p, auto &ctx) const{
		return std::formatter<std::string>::format(p.string(), ctx);
	}
};

template<size_t n>
struct std::formatter<Tins::HWAddress<n>>: std::formatter<std::string>{
	auto format(const Tins::HWAddress<n> &addr, auto &ctx) const{
		return std::formatter<std::string>::format(addr.to_string(), ctx);
	}
};

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

template<typename...Args>
void log(const LogLevel level, std::format_string<std::remove_cvref_t<Args>...> fmt, Args &&...args){
	auto cleaned = std::make_tuple(clean_arg(std::forward<Args>(args))...);
	const std::string msg = [&]<size_t...Is>(std::index_sequence<Is...>){
		return std::vformat(fmt.get(), std::make_format_args(std::get<Is>(cleaned)...));
	}(std::index_sequence_for<Args...>{});
	write_log_message(level, msg);
}

//[[gnu::format(printf, 2, 3)]]
//void log(LogLevel level, const char *fmt, ...);
void log(LogLevel level, const std::string &msg);
void log_actor_map(const std::string &name, const ActorCMap &m);

using LogTimePoint = std::chrono::time_point<std::chrono::system_clock>;

// Returns a nanosecond-precision time_point (system_clock epoch on parse error)
LogTimePoint log_time_to_epoch_ns(const std::string &time_str);
// between_markers -> only @START -> @END/@END_STOP
std::vector<LogTimePoint> get_time_logs(const RunStatus &rs, const std::string &process_name,
										const std::string &pattern, bool between_markers = false
);
std::string escape_tex(std::string text);
}