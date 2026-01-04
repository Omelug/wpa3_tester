#pragma once
#include "log.h"
#include <string>
#include <stdexcept>
#include <cstdarg>

// Base error with printf-style formatting helper
class tester_error : public std::runtime_error {
public:
    explicit tester_error(const std::string& msg);

    // printf-style constructor: formats message and logs at given level
    template<typename... Args>
    tester_error(const LogLevel level, const char *fmt, Args... args)
        : std::runtime_error(vprintf_format(fmt, args...)) {
        log(level, "%s", runtime_error::what());
    }

protected:
    static std::string vprintf_format(const char *fmt, ...);
};

class config_error : public tester_error {
public:
    using tester_error::tester_error;

    explicit config_error(const std::string &msg)
        : tester_error(msg) {
        log(LogLevel::CRITICAL, "%s", runtime_error::what());
    }

    template<typename... Args>
    explicit config_error(const char *fmt, Args... args)
        : tester_error(LogLevel::CRITICAL, fmt, args...) {}
};

class req_error : public tester_error {
public:
    using tester_error::tester_error;

    explicit req_error(const std::string &msg)
        : tester_error(msg) {
        log(LogLevel::ERROR, "%s", runtime_error::what());
    }

    template<typename... Args>
    explicit req_error(const char *fmt, Args... args)
        : tester_error(LogLevel::ERROR, fmt, args...) {}
};

class setup_error : public tester_error {
public:
    using tester_error::tester_error;

    explicit setup_error(const std::string &msg)
        : tester_error(msg) {
        log(LogLevel::CRITICAL, "%s", runtime_error::what());
    }

    template<typename... Args>
    explicit setup_error(const char *fmt, Args... args)
        : tester_error(LogLevel::CRITICAL, fmt, args...) {}
};

class not_implemented_error : public tester_error {
public:
    using tester_error::tester_error;

    explicit not_implemented_error(const std::string &msg)
        : tester_error(msg) {
        log(LogLevel::CRITICAL, "%s", runtime_error::what());
    }

    template<typename... Args>
    explicit not_implemented_error(const char *fmt, Args... args)
        : tester_error(LogLevel::CRITICAL, fmt, args...) {}
};

class headers_error : public tester_error {
public:
    using tester_error::tester_error;

    explicit headers_error(const std::string &msg)
        : tester_error(msg) {
        log(LogLevel::CRITICAL, "%s", runtime_error::what());
    }

    template<typename... Args>
    explicit headers_error(const char *fmt, Args... args)
        : tester_error(LogLevel::CRITICAL, fmt, args...) {}
};