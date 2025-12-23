#pragma once
#include "config/RunStatus.h"

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

void log(LogLevel level, const char *fmt, ...);
void log_actor_map(const char *name, const ActorCMap &m);
