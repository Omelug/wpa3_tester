#include "ProcessManager.h"
#include <memory>
#include <system_error>
#include <map>
#include <iostream>
#include <ranges>
#include <regex>
#include <chrono>
#include <iomanip>
#include <reproc++/drain.hpp>
#include "logger/error_log.h"
#include <thread>

using namespace std;

string current_timestamp() {
    using clock = chrono::system_clock;
    const auto now = clock::now();
    const time_t t = clock::to_time_t(now);
    tm buf{};
    localtime_r(&t, &buf);
    char out[32];
    strftime(out, sizeof(out), "%Y-%m-%d %H:%M:%S", &buf);
    return out;
}

void ProcessManager::write_log_line(ofstream &os, const string &line) {
    os << line << '\n';
    os.flush();
}

void ProcessManager::init_logging(const std::string &run_folder){
    namespace fs = std::filesystem;

    log_base_dir = fs::path(run_folder) / "logger";

    std::error_code ec;
    if (fs::exists(log_base_dir, ec)) {
        fs::remove_all(log_base_dir, ec);
        if (ec) {
            log(LogLevel::ERROR,
                "Failed to clean logger directory: %s: %s",
                log_base_dir.string().c_str(),
                ec.message().c_str());
            throw runtime_error("Unable to clean logger directory");
        }
    }

    fs::create_directories(log_base_dir, ec);
    if (ec) {
        log(LogLevel::ERROR,
            "Failed to create logger directory: %s: %s",
            log_base_dir.string().c_str(),
            ec.message().c_str());
        throw runtime_error("Unable to create logger directory");
    }

    const fs::path combined_path = log_base_dir / "all.log";
    combined_log.close();
    combined_log.open(combined_path, ios::out | ios::trunc);
    if (!combined_log.is_open()) {
        log(LogLevel::ERROR,
            "Failed to open combined log file: %s",
            combined_path.string().c_str());
        throw runtime_error("Unable to open combined log file");
    }

    for (auto &entry: process_logs | views::values) {
        if (entry.log.is_open()) {
            entry.log.close();
        }
        entry.history.clear();
        entry.history_enabled = false;
    }
    process_logs.clear();
    draining_started = false;
}

void ProcessManager::run(const string& name, const vector<string> &cmd) {
    namespace fs = std::filesystem;

    auto proc = make_unique<reproc::process>();
    reproc::options options;
    options.stop.first = { reproc::stop::terminate, reproc::milliseconds(2000) };
    options.stop.second = { reproc::stop::kill, reproc::milliseconds(2000) };

    if (const error_code ec = proc->start(cmd, options)) {
        throw runtime_error("Failed to start " + name + ": " + ec.message());
    }

    const fs::path log_path = log_base_dir / (name + ".log");

    auto &logs = process_logs[name];
    logs.log.close();
    logs.log.open(log_path, ios::out | ios::trunc);
    logs.history.clear();
    // history_enabled default is false until allow_history() is called

    if (!logs.log.is_open()) {
        log(LogLevel::ERROR,
            "Failed to open log for %s: %s",
            name.c_str(), log_path.string().c_str());
    }

    string cmd_line;
    for (size_t i = 0; i < cmd.size(); ++i) {
        if (i) cmd_line += ' ';
        cmd_line += cmd[i];
    }
    const string prefix = current_timestamp() + " [" + name + "] [cmd] ";
    const string line   = prefix + cmd_line;

    if (combined_log.is_open()) {
        write_log_line(combined_log, line);
    }
    if (logs.log.is_open()) {
        write_log_line(logs.log, line);
    }

    processes[name] = std::move(proc);

    if (!draining_started) {
        start_global_drain();
        draining_started = true;
    }
}

void ProcessManager::allow_history(const std::string &name) {
    auto it = process_logs.find(name);
    if (it != process_logs.end()) {
        it->second.history_enabled = true;
    }
}

void ProcessManager::ignore_history(const std::string &name) {
    auto it = process_logs.find(name);
    if (it != process_logs.end()) {
        it->second.history_enabled = false;
        it->second.history.clear();
    }
}

void ProcessManager::discard_history(const std::string &name) {
    auto it = process_logs.find(name);
    if (it != process_logs.end()) {
        it->second.history.clear();
    }
}

void ProcessManager::wait_for(const string &name, const string &pattern){
    const regex re(pattern);

    auto it = process_logs.find(name);
    if (it == process_logs.end()) {
        throw runtime_error("Unknown process in wait_for: " + name);
    }

    // First, scan existing history if enabled
    if (it->second.history_enabled) {
        string &hist = it->second.history;
        stringstream ss(hist);
        string line;
        string new_history;
        bool found = false;

        while (getline(ss, line)) {
            if (regex_search(line, re)) {
                // Discard history up to and including this line
                found = true;
                break;
            }
            // If not yet found, we drop lines; if you want to retain
            // trailing lines after the match, adjust logic accordingly.
        }

        if (found) {
            hist.clear();
            return;
        }
    }

    const auto& proc = processes.at(name);
    string accumulator_out;
    string accumulator_err;
    bool found_new = false;

    auto make_sink = [&](const string& process_name, const string& label, string& accumulator) {
        return [this, process_name, label, &accumulator, &re, &found_new](reproc::stream, const uint8_t* buffer, const size_t size) {
            const string data(reinterpret_cast<const char*>(buffer), size);
            accumulator.append(data);

            const string prefix = current_timestamp() + " [" + process_name + "] [" + label + "] ";

            stringstream ss(data);
            string line;
            while (getline(ss, line)) {
                if (!line.empty()) {
                    const string full_line = prefix + line;

                    if (combined_log.is_open()) {
                        write_log_line(combined_log, full_line);
                    }

                    auto it2 = process_logs.find(process_name);
                    if (it2 != process_logs.end()) {
                        if (it2->second.log.is_open()) {
                            write_log_line(it2->second.log, full_line);
                        }
                        if (it2->second.history_enabled) {
                            it2->second.history.append(line);
                            it2->second.history.push_back('\n');
                        }
                    }

                    if (regex_search(line, re)) {
                        found_new = true;
                        return make_error_code(errc::interrupted);
                    }
                }
            }

            return error_code();
        };
    };

    auto out_sink = make_sink(name, "stdout", accumulator_out);
    auto err_sink = make_sink(name, "stderr", accumulator_err);

    if (const std::error_code ec = reproc::drain(*proc, out_sink, err_sink)) {
        if (ec != errc::interrupted) {
            log(LogLevel::ERROR, "Drain in wait_for failed: %s", ec.message().c_str());
        }
    }

    if(!found_new){
        throw setup_error("output not found (probably end of process)");
    }
    discard_history(name);
}

ProcessManager::~ProcessManager() {
    stop_all();
    combined_log.close();
    for (auto &entry: process_logs | views::values) {
        if (entry.log.is_open()) entry.log.close();
    }
}

void ProcessManager::stop_all() {
    for (auto &proc: processes | views::values) {
        if (proc) {
            reproc::stop_actions operations{};
            operations.first = { reproc::stop::terminate, reproc::milliseconds(1000) };
            operations.second = { reproc::stop::kill, reproc::milliseconds(1000) };
            proc->stop(operations);
        }
    }
    processes.clear();
}
