#pragma once
#include <string>
#include <fstream>
#include <iostream>

#include "config/RunStatus.h"

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

void log(LogLevel level, const char *fmt, ...);
void log_actor_map(const char* name, const ActorCMap& m);
void log_actor_configs(const ActorCMap& m, std::ofstream *ofs = nullptr);


inline void debug_step(){
    bool DEBUG_STEP = true; //TODO
    if(!DEBUG_STEP) return;
    std::cout << "Wait for enter..." << std::flush;
    std::cin.clear();
    std::cin.get();
    std::cout << "ok" << std::endl;
};