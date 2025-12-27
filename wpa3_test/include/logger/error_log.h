#pragma once
#include "log.h"
#include <string>
#include <stdexcept>
#include <format>

using namespace  std;

class tester_error : public std::runtime_error {
public:
    explicit tester_error(const std::string& msg) : std::runtime_error(msg) {}

    template<typename... Args>
    static std::string v_format(const std::string_view fmt, Args&&... args) {
        try {
            return std::vformat(fmt, std::make_format_args(args...));
        } catch (const std::format_error& e) {
            return std::string("Format error: ") + e.what();
        }
    }
};

class config_error : public tester_error {
public:
    template<typename... Args>
    explicit config_error(std::string_view fmt, Args&&... args)
        : tester_error(v_format(fmt, std::forward<Args>(args)...))
    {
        log(LogLevel::CRITICAL, runtime_error::what());
    }
};

class req_error : public tester_error {
public:
    template<typename... Args>
    explicit req_error(std::string_view fmt, Args&&... args)
        : tester_error(v_format(fmt, std::forward<Args>(args)...))
    {
        log(LogLevel::ERROR, runtime_error::what());
    }
};

class setup_error : public tester_error {
public:
    template<typename... Args>
    explicit setup_error(std::string_view fmt, Args&&... args)
        : tester_error(v_format(fmt, std::forward<Args>(args)...))
    {
        log(LogLevel::CRITICAL, runtime_error::what());
    }
};

class not_implemented_error : public tester_error {
public:
    template<typename... Args>
    explicit not_implemented_error(std::string_view fmt, Args&&... args)
        : tester_error(v_format(fmt, std::forward<Args>(args)...))
    {
        log(LogLevel::CRITICAL, runtime_error::what());
    }
};