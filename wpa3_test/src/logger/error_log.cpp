#include "../../include/logger/error_log.h"
#include <cstdarg>
#include <cstdio>
#include <string>
#include <vector>

using namespace std;

config_error config_error::format(const char* fmt, ...) {
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