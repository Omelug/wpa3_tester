#pragma once
#include "log.h"
#include <string>
#include <stdexcept>
#include <format>

//TODO simplify this file

class tester_error : public std::runtime_error {
public:
    explicit tester_error(const std::string& msg);
    static std::string v_format(std::string_view fmt,std::format_args args);
};

class config_error : public tester_error {
public:
    explicit config_error(const std::string& msg);
    template<typename... Args>
    explicit config_error(const std::string_view fmt, Args&&... args)
        : config_error(v_format(fmt, std::make_format_args(args...))) {}
};

class req_error : public tester_error {
public:
    explicit req_error(const std::string& msg);
    template<typename... Args>
    explicit req_error(const std::string_view fmt, Args&&... args)
        : req_error(v_format(fmt, std::make_format_args(args...))) {}
};

class setup_error : public tester_error {
public:
    explicit setup_error(const std::string& msg);
    template<typename... Args>
    explicit setup_error(const std::string_view fmt, Args&&... args)
        : setup_error(v_format(fmt, std::make_format_args(args...))) {}
};

class not_implemented_error : public tester_error {
public:
    explicit not_implemented_error(const std::string& msg);
    template<typename... Args>
    explicit not_implemented_error(const std::string_view fmt, Args&&... args)
        : not_implemented_error(v_format(fmt, std::make_format_args(args...))) {}
};

class headers_error : public tester_error {
public:
    explicit headers_error(const std::string& msg);
    template<typename... Args>
    explicit headers_error(const std::string_view fmt, Args&&... args)
        : headers_error(v_format(fmt, std::make_format_args(args...))) {}
};