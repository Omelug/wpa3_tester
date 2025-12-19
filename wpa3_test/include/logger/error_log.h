#pragma once

#include <exception>
#include <string>
#include <cstdarg>
#include <stdexcept>
#include <vector>

using namespace  std;
class config_error : public runtime_error {
public:
    explicit config_error(const string& msg): runtime_error(msg) {}

    static config_error format(const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);

        va_list args_copy;
        va_copy(args_copy, args);
        int size = vsnprintf(nullptr, 0, fmt, args_copy);
        va_end(args_copy);

        vector<char> buf(size + 1);
        vsnprintf(buf.data(), buf.size(), fmt, args);
        va_end(args);


        return config_error(string(buf.data()));
    }
};