#include "../../include/logger/log.h"
#include "../../include/logger/error_log.h"

#include <cstdarg>
#include <cstdio>
#include <iostream>
#include <vector>

const char *levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:    return "DEBUG";
        case LogLevel::INFO:     return "INFO";
        case LogLevel::WARNING:  return "WARNING";
        case LogLevel::ERROR:    return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN"; 
}

void log(const LogLevel level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list args_copy;
    va_copy(args_copy, args);
    const int size = vsnprintf(nullptr, 0, fmt, args_copy);
    va_end(args_copy);
    if (size < 0) {
        va_end(args);
        throw runtime_error("vsnprintf failed");
    }

    vector<char> buf(size + 1);
    vsnprintf(buf.data(), buf.size(), fmt, args);
    va_end(args);

    const string msg(buf.data());
    cerr << levelToString(level) << ": " << msg << endl;
}
