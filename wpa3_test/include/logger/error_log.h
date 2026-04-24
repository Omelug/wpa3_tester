#pragma once
#include "log.h"
#include <string>
#include <stdexcept>
#include <cstdarg>

namespace wpa3_tester{
class tester_error: public std::runtime_error{
public:
    explicit tester_error(const std::string &msg);

    template<typename...Args>
    tester_error(const LogLevel level, const char *fmt, Args...args)
        : std::runtime_error(vprintf_format(fmt, args...)){
        log(level, "{}", std::runtime_error::what());
    }
protected:
    static std::string vprintf_format(const char *fmt, ...);
};

template<LogLevel Level>
class typed_error: public tester_error{
public:
    explicit typed_error(const std::string &msg)
        : tester_error(msg){
        log(Level, "{}", std::runtime_error::what());
    }

    template<typename...Args>
    explicit typed_error(const char *fmt, Args...args)
        : tester_error(Level, fmt, args...){}
};

using config_err = typed_error<LogLevel::CRITICAL>;
using compile_err = typed_error<LogLevel::CRITICAL>;
using install_err = typed_error<LogLevel::CRITICAL>;

using req_err = typed_error<LogLevel::CRITICAL>;
using run_err = typed_error<LogLevel::CRITICAL>;
using setup_err = typed_error<LogLevel::CRITICAL>;
using scan_err = typed_error<LogLevel::CRITICAL>;
using stats_err = typed_error<LogLevel::ERROR>;

using not_implemented_err = typed_error<LogLevel::CRITICAL>;
using timeout_err = typed_error<LogLevel::ERROR>;

using ex_conn_err = typed_error<LogLevel::CRITICAL>;
}