#pragma once
#include "log.h"
#include <string>
#include <stdexcept>
#include <format>
#include <string>
#include <vector>

using namespace  std;
class config_error : public runtime_error {
public:
    explicit config_error(const string& msg): runtime_error(msg){
        log(LogLevel::CRITICAL, msg.c_str());
    }

    template<typename... Args>
    static config_error format(std::string_view fmt, Args&&... args) {
        try {
            return config_error(std::vformat(fmt, std::make_format_args(args...)));
        } catch (const std::format_error& e) {
            return config_error(std::string("Format error in template: ") + e.what());
        }
    }
};