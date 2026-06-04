#pragma once
#include <string>
#include <fstream>
#include <iostream>
#include <cstdint>
#include <chrono>

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
void write_log_message(LogLevel level, const std::string &msg);

template<typename...Args>
void log(const LogLevel level, std::format_string<Args...> fmt, Args &&...args){
	const std::string msg = std::format(fmt, std::forward<Args>(args)...);
	write_log_message(level, msg);
}

//__attribute__((format(printf, 2, 3)))
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