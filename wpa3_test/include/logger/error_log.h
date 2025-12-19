#pragma once

#include <string>
#include <stdexcept>

using namespace  std;
class config_error : public runtime_error {
public:
    explicit config_error(const string& msg): runtime_error(msg) {}
    static config_error format(const char* fmt, ...);
};