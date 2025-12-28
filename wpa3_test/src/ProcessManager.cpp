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

    // open combined log file <run_folder>/logger/all.log
    const fs::path combined_path = log_base_dir / "all.log";
    combined_log.close();
    combined_log.open(combined_path, ios::out | ios::trunc);
    if (!combined_log.is_open()) {
        log(LogLevel::ERROR,
            "Failed to open combined log file: %s",
            combined_path.string().c_str());
        throw runtime_error("Unable to open combined log file");
    }

    // close and clear any per-process log files from a previous run
    for (auto &val: process_logs | views::values) {
        if (val.stdout_log.is_open()) {
            val.stdout_log.close();
        }
        if (val.stderr_log.is_open()) {
            val.stderr_log.close();
        }
    }
    process_logs.clear();
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

    // prepare per-process log files and remember them
    fs::path stdout_path = log_base_dir / (name + ".stdout.log");
    fs::path stderr_path = log_base_dir / (name + ".stderr.log");

    auto &logs = process_logs[name];

    logs.stdout_log.close();
    logs.stderr_log.close();

    logs.stdout_log.open(stdout_path, ios::out | ios::trunc);
    if (!logs.stdout_log.is_open()) {
        log(LogLevel::ERROR,
            "Failed to open stdout log for %s: %s",
            name.c_str(), stdout_path.string().c_str());
    }

    logs.stderr_log.open(stderr_path, ios::out | ios::trunc);
    if (!logs.stderr_log.is_open()) {
        log(LogLevel::ERROR,
            "Failed to open stderr log for %s: %s",
            name.c_str(), stderr_path.string().c_str());
    }

    // log the start command to both per-process logs and combined log
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
    if (logs.stdout_log.is_open()) {
        write_log_line(logs.stdout_log, line);
    }

    processes[name] = std::move(proc);
}

void ProcessManager::wait_for(const string &name, const string &pattern){
    const auto& proc = processes.at(name);
    string accumulator_out;
    string accumulator_err;
    const regex re(pattern);
    bool found = false;

    auto make_sink = [&](const string& process_name, const string& label, string& accumulator) {
        return [this, process_name, label, &accumulator, re, &found](reproc::stream, const uint8_t* buffer, const size_t size) {
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

                    auto it = process_logs.find(process_name);
                    if (it != process_logs.end()) {
                        std::ofstream *target = nullptr;
                        if (label == "stdout") {
                            target = &it->second.stdout_log;
                        } else if (label == "stderr") {
                            target = &it->second.stderr_log;
                        }
                        if (target && target->is_open()) {
                            write_log_line(*target, full_line);
                        }
                    }
                }
                if (regex_search(line, re)) {
                    found = true;
                    return make_error_code(errc::interrupted);
                }
            }

            return error_code();
        };
    };

    auto out_sink = make_sink(name, "stdout", accumulator_out);
    auto err_sink = make_sink(name, "stderr", accumulator_err);

    if (const std::error_code ec = reproc::drain(*proc, out_sink, err_sink)) {
        if (ec != errc::interrupted) {
            log(LogLevel::ERROR, "Drain failed: %s", ec.message().c_str());
        }
    }

    if(!found){
        throw setup_error("output not found (probably end of process)");
    }
}

ProcessManager::~ProcessManager() {
    stop_all();
    combined_log.close();
    for (auto &[stdout_log, stderr_log]: process_logs | views::values) {
        if (stdout_log.is_open()) stdout_log.close();
        if (stderr_log.is_open()) stderr_log.close();
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
