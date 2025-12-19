#pragma once

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

void log(LogLevel level, const char *fmt, ...);
