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

void log_actor_configs(const ActorCMap& m) {
    for (const auto& [name, actor] : m) {
        log(LogLevel::DEBUG,
            "Actor '%s': iface=%s, mac=%s, essid=%s, driver=%s",
            name.c_str(),
            opt_or(actor->str_con["iface"], "<none>"),
            opt_or(actor->str_con["mac"], "<none>"),
            opt_or(actor->str_con["essid"], "<none>"),
            opt_or(actor->str_con["driver"], "<none>"));

		string cond_str;
        bool first = true;
        for (const auto &[cond_name, bool_v] : actor->bool_conditions) {
            string val_repr = "None";
            if (bool_v.has_value()) {val_repr = (*bool_v ? "true" : "false");}
            if (!first) {cond_str += ", ";}
            cond_str += cond_name + "=" + val_repr;
            first = false;
        }
        if (cond_str.empty()) {cond_str = "<no conditions>";}
        log(LogLevel::DEBUG,"Actor '%s' conditions: %s", name.c_str(), cond_str.c_str());
    }
    if (m.empty()) {log(LogLevel::DEBUG, "Actor map is empty");}
}

// mapping of actors -> iface to run_folder/mapping.txt
void save_actor_interface_mapping(const std::string &run_folder,
                                  const ActorCMap &internal_actors) {
    if (run_folder.empty()) {
        log(LogLevel::WARNING, "save_actor_interface_mapping: run_folder not set");
        return;
    }

    const string path = run_folder + "/mapping.txt";
    ofstream ofs(path, ios::out | ios::trunc);
    if (!ofs) {
        log(LogLevel::ERROR, "Failed to open %s for writing actor/interface mapping", path.c_str());
        return;
    }

    ofs << "# Actor to interface mapping" << std::endl;
    for (const auto &[name, actor] : internal_actors) {
        const char *iface = opt_or(actor->str_con["iface"], "<none>");
        ofs << name << " -> " << iface << std::endl;
    }

    ofs.close();
    log(LogLevel::INFO, "Actor/interface mapping written to %s", path.c_str());
}
