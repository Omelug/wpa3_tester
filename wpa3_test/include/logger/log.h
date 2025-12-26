#pragma once
#include <string>
#include <optional>
#include "config/Actor_config.h"
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
