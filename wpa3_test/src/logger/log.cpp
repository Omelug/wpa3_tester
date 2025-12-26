#include "../../include/logger/log.h"
#include "../../include/logger/error_log.h"

#include <cstdarg>
#include <cstdio>
#include <iostream>
#include <vector>

#include "config/RunStatus.h"

const char *levelToString(LogLevel level) {
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

static const char* opt_or(const std::optional<std::string>& v, const char* fallback) {
    return v.has_value() ? v->c_str() : fallback;
}

void log_actor_configs(const ActorCMap& m) {
    for (const auto& [name, actor] : m) {
        log(LogLevel::DEBUG,
            "Actor '%s': iface=%s, mac=%s, essid=%s, driver=%s",
            name.c_str(),
            opt_or(actor->iface, "<none>"),
            opt_or(actor->mac, "<none>"),
            opt_or(actor->essid, "<none>"),
            opt_or(actor->driver, "<none>"));

		string cond_str;
        bool first = true;
        for (const auto &entry : actor->bool_conditions) {
            const string &key = entry.first;
            const auto &val_opt = entry.second;
            string val_repr = "_";
            if (val_opt.has_value()) {val_repr = (*val_opt ? "true" : "false");}
            if (!first) {cond_str += ", ";}
            cond_str += key + "=" + val_repr;
            first = false;
        }
        if (cond_str.empty()) {cond_str = "<no conditions>";}
        log(LogLevel::DEBUG,"Actor '%s' conditions: %s",name.c_str(), cond_str.c_str());
    }
    if (m.empty()) {log(LogLevel::DEBUG, "Actor map is empty");}
}
