#include "logger/log.h"
#include "logger/error_log.h"

#include <cstdarg>
#include <cstdio>
#include <iostream>
#include <ctime>
#include <regex>
#include <vector>

#include "config/RunStatus.h"
namespace wpa3_tester{
    using namespace std;

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
        using namespace std;
        va_list args;
        va_start(args, fmt);
        va_list args_copy;
        va_copy(args_copy, args);
        const int size = vsnprintf(nullptr, 0, fmt, args_copy);
        va_end(args_copy);
        if (size < 0) {
            va_end(args);
            throw std::runtime_error("vsnprintf failed");
        }

        std::vector<char> buf(size + 1);
        vsnprintf(buf.data(), buf.size(), fmt, args);
        va_end(args);

        const string msg(buf.data());
        cerr << levelToString(level) << ": " << msg << endl;
    }

    void log_actor_map(const char* name, const ActorCMap& m) {
        std::string keys;
        bool first = true;
        for (const auto &k: m | std::views::keys) {
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

    void log_actor_configs(const ActorCMap& m, std::ofstream& ofs) {
        for (const auto &[name, actor] : m) {
            ofs << "\t" << name << " -> " << (*actor)["iface"] << std::endl;
        }
        for (const auto& [name, actor] : m) {
            // Build a human-readable line
            const string line =
                "Actor '" + name + "': iface=" + opt_or(actor->str_con.at("iface"), "<none>") +
                ", mac="    + opt_or(actor->str_con.at("mac"),   "<none>") +
                ", essid="  + opt_or(actor->str_con.at("essid"), "<none>") +
                ", driver=" + opt_or(actor->str_con.at("driver"),"<none>");

            //log(LogLevel::DEBUG, "%s", line.c_str());

            if (ofs.is_open()) {
                ofs << line << std::endl;
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
            if (ofs.is_open()) {
                ofs << "  conditions: " << cond_str << std::endl;
            }
        }

        if (m.empty()) {
            log(LogLevel::DEBUG, "Actor map is empty");
            if (ofs.is_open()) {
                ofs << "<empty actor map>" << std::endl;
            }
        }
    }

    double log_time_to_epoch(const std::string& time_str) {
        std::tm t = {};
        if (strptime(time_str.c_str(), "%Y-%m-%d %H:%M:%S", &t) == nullptr) {
            return 0.0;
        }
        t.tm_isdst = -1;
        return static_cast<double>(std::mktime(&t));
    }

    std::vector<double> get_time_logs(const RunStatus& rs, const std::string& actor_name, const std::string& pattern) {
        using namespace std;
        vector<double> timestamps;
        string actor_log = filesystem::path(rs.run_folder) / "logger" / (actor_name +".log");
        ifstream file(actor_log);
        string line;
        regex re(R"(^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*)" + pattern);
        smatch match;

        while (getline(file, line)) {
            if (regex_search(line, match, re)) {
                double epoch = log_time_to_epoch(match[1].str());
                if (epoch > 0) timestamps.push_back(epoch);
            }
        }
        return timestamps;
    }

    std::string escape_tex(std::string text) {
        size_t pos = 0;
        while ((pos = text.find("_", pos)) != std::string::npos) {
            text.replace(pos, 1, "\\_");
            pos += 2;
        }
        return text;
    }

}