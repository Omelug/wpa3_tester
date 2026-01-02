#include "../../include/logger/log.h"
#include "../../include/logger/error_log.h"

#include <cstdarg>
#include <cstdio>
#include <iostream>

#include "config/RunStatus.h"

using namespace  std;

const char *levelToString(const LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:    return "DEBUG";
        case LogLevel::INFO:     return "INFO";
        case LogLevel::WARNING:  return "WARNING";
        case LogLevel::ERROR:    return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN"; 
}

void log(const LogLevel level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list args_copy;
    va_copy(args_copy, args);
    const int size = vsnprintf(nullptr, 0, fmt, args_copy);
    va_end(args_copy);
    if (size < 0) {
        va_end(args);
        throw runtime_error("vsnprintf failed");
    }

    vector<char> buf(size + 1);
    vsnprintf(buf.data(), buf.size(), fmt, args);
    va_end(args);

    const string msg(buf.data());
    cerr << levelToString(level) << ": " << msg << endl;
}

void log_actor_map(const char* name, const ActorCMap& m) {
    std::string keys;
    bool first = true;
    for (const auto &k: m | views::keys) {
        if (!first) keys += ", ";
        keys += k;
        first = false;
    }
    if (keys.empty()) {
        keys = "<empty>";
    }
    log(LogLevel::DEBUG, "%s: %s", name, keys.c_str());
}

static auto opt_or(const std::optional<std::string> &v, const char *fallback)->const char *{
    return v.has_value() ? v->c_str() : fallback;
}

void log_actor_configs(const ActorCMap& m, ofstream *ofs) {
    for (const auto& [name, actor] : m) {
        // Build a human-readable line
        const string line =
            "Actor '" + name + "': iface=" + opt_or(actor->str_con.at("iface"), "<none>") +
            ", mac="    + opt_or(actor->str_con.at("mac"),   "<none>") +
            ", essid="  + opt_or(actor->str_con.at("essid"), "<none>") +
            ", driver=" + opt_or(actor->str_con.at("driver"),"<none>");

        //log(LogLevel::DEBUG, "%s", line.c_str());

        if (ofs && ofs->is_open()) {
            (*ofs) << line << std::endl;
        }

        string cond_str;
        bool first = true;
        for (const auto &[cond_name, bool_v] : actor->bool_conditions) {
            string val_repr = "None";
            if (bool_v.has_value()) { val_repr = (*bool_v ? "true" : "false"); }
            if (!first) { cond_str += ", "; }
            cond_str += cond_name + "=" + val_repr;
            first = false;
        }
        if (cond_str.empty()) { cond_str = "<no conditions>"; }

        log(LogLevel::DEBUG, "Actor '%s' conditions: %s", name.c_str(), cond_str.c_str());
        if (ofs && ofs->is_open()) {
            (*ofs) << "  conditions: " << cond_str << std::endl;
        }
    }

    if (m.empty()) {
        log(LogLevel::DEBUG, "Actor map is empty");
        if (ofs && ofs->is_open()) {
            (*ofs) << "<empty actor map>" << std::endl;
        }
    }
}
