#pragma once
#include "log.h"
#include <string>
#include <stdexcept>
#include <cstdarg>

namespace wpa3_tester{
    class tester_error : public std::runtime_error {
    public:
        explicit tester_error(const std::string& msg);

        template<typename... Args>
        tester_error(const LogLevel level, const char *fmt, Args... args)
            : std::runtime_error(vprintf_format(fmt, args...)) {
            log(level, "%s", std::runtime_error::what());
        }

    protected:
        static std::string vprintf_format(const char *fmt, ...);
    };

    template<LogLevel Level>
    class typed_error : public tester_error {
    public:
        explicit typed_error(const std::string& msg)
            : tester_error(msg) {
            log(Level, "%s", std::runtime_error::what());
        }

        template<typename... Args>
        explicit typed_error(const char *fmt, Args... args)
            : tester_error(Level, fmt, args...) {}
    };
    //TODO přepsat error -> err pro zkrácení řádků
    using config_error          = typed_error<LogLevel::CRITICAL>;
    using compile_error         = typed_error<LogLevel::CRITICAL>;
    using install_error         = typed_error<LogLevel::CRITICAL>;

    using req_error             = typed_error<LogLevel::CRITICAL>;

    using setup_error           = typed_error<LogLevel::CRITICAL>;

    using not_implemented_error = typed_error<LogLevel::CRITICAL>;
    using wait_for_timeout      = typed_error<LogLevel::ERROR>;

    using ex_conn_err         = typed_error<LogLevel::CRITICAL>;
}