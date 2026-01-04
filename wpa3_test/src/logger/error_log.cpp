#include "logger/error_log.h"
#include <vector>
#include <cstdio>

using namespace std;

tester_error::tester_error(const string &msg): runtime_error(msg){}

string tester_error::vprintf_format(const char *fmt, ...){
    va_list ap;
    va_start(ap, fmt);
    va_list ap_copy;
    va_copy(ap_copy, ap);
    const int len = vsnprintf(nullptr, 0, fmt, ap_copy);
    va_end(ap_copy);
    if(len < 0){
        va_end(ap);
        return "printf format error";
    }
    vector<char> buf(static_cast<size_t>(len) + 1);
    vsnprintf(buf.data(), buf.size(), fmt, ap);
    va_end(ap);
    return string(buf.data());
}
