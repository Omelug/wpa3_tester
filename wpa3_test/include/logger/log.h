#pragma once
#include <string>
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
void log_actor_configs(const ActorCMap& m);
void save_actor_interface_mapping(const std::string &run_folder,const ActorCMap &internal_actors);
