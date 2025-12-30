#include "logger/error_log.h"
#include <format>

using namespace std;

// Base error constructor
tester_error::tester_error(const string &msg): runtime_error(msg){}

// Format helper implementation
string tester_error::v_format(const string_view fmt, const format_args args){
    try{return vformat(fmt, args);
    } catch(const format_error &e){return string("Format error: ") + e.what();
    }
}

// Concrete error types
config_error::config_error(const string &msg): tester_error(msg){
    log(LogLevel::CRITICAL, runtime_error::what());
}

req_error::req_error(const string &msg): tester_error(msg){
    log(LogLevel::ERROR, runtime_error::what());
}

setup_error::setup_error(const string &msg): tester_error(msg){
    log(LogLevel::CRITICAL, runtime_error::what());
}

not_implemented_error::not_implemented_error(const string &msg): tester_error(msg){
    log(LogLevel::CRITICAL, runtime_error::what());
}
