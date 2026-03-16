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
    using namespace std::chrono;

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
            throw runtime_error("vsnprintf failed");
        }

        vector<char> buf(size + 1);
        vsnprintf(buf.data(), buf.size(), fmt, args);
        va_end(args);

        const string msg(buf.data());
        cerr << levelToString(level) << ": " << msg << endl;
    }

    void log(const LogLevel level, const std::string& msg) {
        cerr << levelToString(level) << ": " << msg << endl;
    }

    void log_actor_map(const string &name, const ActorCMap& m) {
        string keys;
        bool first = true;
        for (const auto &k: m | views::keys) {
            if (!first) keys += ", ";
            keys += k;
            first = false;
        }
        if (keys.empty()) {keys = "<empty>";}
        log(LogLevel::DEBUG, name+":"+ keys);
    }

    void log_actor_configs(const ActorCMap& m, ofstream& ofs) {
        for (const auto &[name, actor] : m) {
            ofs << "\t" << name << " -> " << actor["iface"] << endl;
        }
        for (const auto& [name, actor] : m) {
            // Build a human-readable line
            const string line =
                "Actor '" + name + "': iface=" + actor->str_con.at("iface").value_or("<none>") +
                ", mac="    + actor->str_con.at("mac").value_or("<none>") +
                ", essid="  + actor->str_con.at("ssid").value_or("<none>") +
                ", driver=" + actor->str_con.at("driver").value_or("<none>");

            //log(LogLevel::DEBUG, "%s", line.c_str());

            if (ofs.is_open()) {ofs << line << endl;}

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

            log(LogLevel::DEBUG, "Actor '"+name+"' conditions: "+cond_str);
            if (ofs.is_open()) {
                ofs << "  conditions: " << cond_str << endl;
            }
        }

        if (m.empty()) {
            log(LogLevel::DEBUG, "Actor map is empty");
            if (ofs.is_open()) {
                ofs << "<empty actor map>" << endl;
            }
        }
    }

    // Returns a nanosecond-precision time_point (epoch == error sentinel)
    LogTimePoint log_time_to_epoch_ns(const string& time_str) {
        tm t = {};
        const char* p = strptime(time_str.c_str(), "%Y-%m-%dT%H:%M:%S", &t);
        if (p == nullptr) return LogTimePoint{};

        // parse fractional seconds ".310201504" → nanoseconds
        int64_t frac_ns = 0;
        if (*p == '.') {
            ++p;
            int64_t scale = 100'000'000; // first digit = 100ms in ns
            while (isdigit(*p) && scale > 0) {
                frac_ns += (*p - '0') * scale;
                scale /= 10;
                ++p;
            }
            while (isdigit(*p)) ++p;
        }

        // parse timezone offset "+0100" / "-0500"
        int tz_offset_sec = 0;
        if (*p == '+' || *p == '-') {
            const int sign = (*p == '+') ? 1 : -1;
            ++p;
            int hhmm = 0;
            for (int i = 0; i < 4 && isdigit(*p); ++i, ++p)
                hhmm = hhmm * 10 + (*p - '0');
            tz_offset_sec = sign * ((hhmm / 100) * 3600 + (hhmm % 100) * 60);
        }

        t.tm_isdst = 0;
        const time_t epoch_sec = timegm(&t) - tz_offset_sec;
        const auto total_ns = static_cast<int64_t>(epoch_sec) * 1'000'000'000LL + frac_ns;
        return LogTimePoint{nanoseconds{total_ns}};
    }

    vector<LogTimePoint> get_time_logs(const RunStatus& rs, const string& process_name, const string& pattern) {
        vector<LogTimePoint> timestamps;
        const string actor_log = filesystem::path(rs.run_folder) / "logger" / (process_name + ".log");
        if (!filesystem::exists(actor_log)) {
            log(LogLevel::ERROR, "Could not find file '" + actor_log + "'");
            return {};
        }
        ifstream file(actor_log);
        string line;
        regex re(R"(^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{4}).*)" + pattern);
        smatch match;

        while (getline(file, line)) {
            if (regex_search(line, match, re)) {
                const LogTimePoint tp = log_time_to_epoch_ns(match[1].str());
                if (tp.time_since_epoch().count() != 0) timestamps.push_back(tp);
            }
        }
        return timestamps;
    }

    string escape_tex(string text) {
        size_t pos = 0;
        while ((pos = text.find("_", pos)) != string::npos) {
            text.replace(pos, 1, "\\_");
            pos += 2;
        }
        return text;
    }

}