#include "ProcessManager.h"
#include <memory>
#include <system_error>
#include <map>
#include <iostream>
#include <ranges>
#include <regex>
#include <chrono>
#include <iomanip>

#include "logger/error_log.h"

using namespace std;

namespace {
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
    fs::path combined_path = log_base_dir / "all.log";
    combined_log.close();
    combined_log.open(combined_path, ios::out | ios::trunc);
    if (!combined_log.is_open()) {
        log(LogLevel::ERROR,
            "Failed to open combined log file: %s",
            combined_path.string().c_str());
        throw runtime_error("Unable to open combined log file");
    }
}

void ProcessManager::run(const string& name, const vector<string> &cmd) {
    auto proc = make_unique<reproc::process>();
    reproc::options options;
    options.stop.first = { reproc::stop::terminate, reproc::milliseconds(2000) };
    options.stop.second = { reproc::stop::kill, reproc::milliseconds(2000) };

    if (const error_code ec = proc->start(cmd, options)) {
        throw runtime_error("Failed to start " + name + ": " + ec.message());
    }

    processes[name] = std::move(proc);
}

void ProcessManager::wait_for(const string &name, const string &pattern) const{
    auto& proc = processes.at(name);
    string accumulator_out;
    string accumulator_err;
    const regex re(pattern);
    bool found = false;

    auto make_sink = [&](const string& process_name, const string& label, string& accumulator) {
        return [process_name, label, &accumulator, re, &found](reproc::stream, const uint8_t* buffer, const size_t size) {
            const string data(reinterpret_cast<const char*>(buffer), size);
            accumulator.append(data);

            const string prefix = current_timestamp() + " [" + process_name + "] [" + label + "] ";
        
            stringstream ss(data);
            string line;
            while (getline(ss, line)) {
                if (!line.empty()) {
                    cout << prefix << line << endl;
                }
                if (regex_search(line, re)) {
                    found = true;
                    return make_error_code(errc::interrupted);
                }
            }

            return error_code();
        };
    };

    auto out_sink = make_sink("access_point", "stdout", accumulator_out);
    auto err_sink = make_sink("access_point", "stderr", accumulator_err); 

    reproc::drain(*proc, out_sink, err_sink);

    if(!found){
        throw setup_error("output not found (probably end of process)");
    }
}

ProcessManager::~ProcessManager() {
    stop_all();
    combined_log.close();
}

void ProcessManager::stop_all() {
    for (auto &proc: processes | views::values) {
        if (proc) {
            reproc::stop_actions operations;
            operations.first = { reproc::stop::terminate, reproc::milliseconds(1000) };
            operations.second = { reproc::stop::kill, reproc::milliseconds(1000) };
            proc->stop(operations);
        }
    }
    processes.clear();
}
