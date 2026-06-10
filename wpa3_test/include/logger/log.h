#pragma once
#include <chrono>
#include <fstream>
#include <iostream>
#include <string>

#include "config/RunStatus.h"

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
template <typename T>
requires std::is_enum_v<std::decay_t<T>>
auto clean_arg(T&& arg) {
	return static_cast<std::underlying_type_t<std::decay_t<T>>>(arg);
}

template <typename T>
requires (!std::is_enum_v<std::decay_t<T>>)
std::decay_t<T> clean_arg(T&& arg) {
	return std::forward<T>(arg);
}

template<typename... Args>
void log(const LogLevel level, std::format_string<std::remove_cvref_t<Args>...> fmt, Args &&... args) {
	auto cleaned = std::make_tuple(clean_arg(std::forward<Args>(args))...);
	const std::string msg = std::apply([&fmt](auto &... a) {
		return std::vformat(fmt.get(), std::make_format_args(a...));
	}, cleaned);
	write_log_message(level, msg);
}

//[[gnu::format(printf, 2, 3)]]
//void log(LogLevel level, const char *fmt, ...);
void log(LogLevel level, const std::string &msg);
void log_actor_map(const std::string &name, const ActorCMap &m);

inline void debug_step(){
	std::cout << "Wait for enter..." << std::flush;
	std::cin.clear();
	std::cin.get();
	std::cout << "ok" << std::endl;
}

using LogTimePoint = std::chrono::time_point<std::chrono::system_clock>;

// Returns a nanosecond-precision time_point (system_clock epoch on parse error)
LogTimePoint log_time_to_epoch_ns(const std::string &time_str);
std::vector<LogTimePoint> get_time_logs(const RunStatus &rs, const std::string &process_name, const std::string &pattern,
                                        bool between_markers = false);
std::string escape_tex(std::string text);
}