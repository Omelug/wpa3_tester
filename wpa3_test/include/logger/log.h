#pragma once
#include <string>
#include <fstream>
#include <iostream>
#include <cstdint>
#include <chrono>

#include "config/RunStatus.h"
namespace wpa3_tester{
    enum class LogLevel {
        DEBUG,
        INFO,
        WARNING,
        ERROR,
        CRITICAL
    };

    void log(LogLevel level, const char *fmt, ...);
    void log_actor_map(const char* name, const ActorCMapU& m);
    void log_actor_configs(const ActorCMap& m, std::ofstream& ofs);


    inline void debug_step(){
        bool DEBUG_STEP = true; //TODO
        if(!DEBUG_STEP) return;
        std::cout << "Wait for enter..." << std::flush;
        std::cin.clear();
        std::cin.get();
        std::cout << "ok" << std::endl;
    }
    using LogTimePoint = std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds>;

    // Returns a nanosecond-precision time_point (system_clock epoch on parse error)
    LogTimePoint log_time_to_epoch_ns(const std::string& time_str);
    std::vector<LogTimePoint> get_time_logs(const RunStatus& rs, const std::string& process_name, const std::string& pattern);
    std::string escape_tex(std::string text);
}