#include "system/ProcessManager.h"
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
    os << line << endl;
}

static error_code handle_chunk(ProcessManager *pm,
                               const string &process_name,
                               const string &label,
                               const string &data)
{
    const string prefix = current_timestamp() + " [" + process_name + "] [" + label + "] ";

    stringstream ss(data);
    string line;
    while (getline(ss, line)) {
        if (line.empty()) continue;
        const string full_line = prefix + line;

        if (pm->combined_log.is_open()) {
            ProcessManager::write_log_line(pm->combined_log, full_line);
        }

        if (auto it = pm->process_logs.find(process_name); it != pm->process_logs.end()) {
            auto &[log, history, history_enabled, wait] = it->second;
            if (log.is_open()) {ProcessManager::write_log_line(log, full_line);}
            if (history_enabled) {
                history += line;
                history.push_back('\n');
            }

            // notify active wait listener, if any
            if (wait.active) {
                if (regex_search(line, wait.pattern)) {
                    wait.matched = true;
                    unique_lock lock(pm->wait_mutex);
                    pm->wait_cv.notify_all();
                }
            }
        }
    }
    return {};
}

void ProcessManager::recreate_log_folder(const std::filesystem::path &log_base_dir){
    namespace fs = filesystem;
    error_code ec;

    // if log folder exists -> clear
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

    // create log folder
    fs::create_directories(log_base_dir, ec);
    if (ec) {
        log(LogLevel::ERROR,
            "Failed to create logger directory: %s: %s",
            log_base_dir.string().c_str(),
            ec.message().c_str());
        throw runtime_error("Unable to create logger directory");
    }

}

void ProcessManager::init_logging(const string &run_folder){
    namespace fs = filesystem;

    log_base_dir = fs::path(run_folder) / "logger";
    recreate_log_folder(log_base_dir);

    // create combated log
    const fs::path combined_path = log_base_dir / "combined.log";
    combined_log.close();
    combined_log.open(combined_path, ios::out | ios::trunc);
    if (!combined_log.is_open()) {
        log(LogLevel::ERROR,
            "Failed to open combined log file: %s",
            combined_path.string().c_str());
        throw runtime_error("Unable to open combined log file");
    }

    for (auto &entry: process_logs | views::values) {
        if (entry.log.is_open()) {entry.log.close();}
        entry.history.clear();
        entry.history_enabled = false;
    }
    process_logs.clear();
}


void ProcessManager::run(const string& actor_name,
                         const vector<string> &cmd,
                         const filesystem::path &working_dir) {
    namespace fs = filesystem;

    auto proc = make_unique<reproc::process>();
    reproc::options options;
    options.stop.first = { reproc::stop::terminate, reproc::milliseconds(2000) };
    options.stop.second = { reproc::stop::kill, reproc::milliseconds(2000) };

    std::string working_dir_str;
    if (!working_dir.empty()) {
        working_dir_str = working_dir.string();
        options.working_directory = working_dir_str.c_str();
    }

    if (const error_code ec = proc->start(cmd, options)) {
        throw runtime_error("Failed to start " + actor_name + ": " + ec.message());
    }

    fs::path log_dir = log_base_dir;
    if (!working_dir_str.empty()) {log_dir = fs::path(working_dir_str);}
    const fs::path log_path = log_dir / (actor_name + ".log");

    auto &logs = process_logs[actor_name];
    logs.log.close();
    logs.log.open(log_path, ios::out | ios::trunc);
    logs.history.clear();

    if (!logs.log.is_open()) {
        log(LogLevel::ERROR,
            "Failed to open log for %s: %s",
            actor_name.c_str(), log_path.string().c_str());
    }

    string cmd_line;
    for (size_t i = 0; i < cmd.size(); ++i) {
        if (i) cmd_line += ' ';
        cmd_line += cmd[i];
    }
    const string line   =  current_timestamp() + " [" + actor_name + "] [cmd] " + cmd_line;

    if (combined_log.is_open()) {write_log_line(combined_log, line);} // stays in global logger folder
    if (logs.log.is_open())     {write_log_line(logs.log, line);}

    processes[actor_name] = std::move(proc);
    start_drain_for(actor_name);
}
void ProcessManager::start_drain_for(const std::string &actor_name) {
    const auto it = processes.find(actor_name);
    if (it == processes.end() || !it->second) return;

    auto proc = it->second.get();

    std::thread([this, actor_name, proc]() {
        uint8_t buffer[4096];

        std::pair<reproc::stream, std::string_view> streams[] = {
            {reproc::stream::out, "stdout"},
            {reproc::stream::err, "stderr"}
        };

        while (true) {
            auto [events, ec] = proc->poll(reproc::event::out | reproc::event::err, reproc::infinite);
            if (ec) break;

            for (auto [stream, name] : streams) {
                if (const auto event = (stream == reproc::stream::out)
                    ? reproc::event::out : reproc::event::err; events & event) {

                    auto [n, read_ec] = proc->read(stream, buffer, sizeof(buffer));
                    if (read_ec) {continue; }

                    if (n > 0) {
                        handle_chunk(this,
                            actor_name, name.data(),
                            string(reinterpret_cast<char*>(buffer), n));
                    }
                }
            }
        }
    }).detach();
}



void ProcessManager::allow_history(const string &actor_name) {
    if (const auto it = process_logs.find(actor_name); it != process_logs.end()) {
        it->second.history_enabled = true;
        return;
    }
    throw setup_error("Process {} not found to allow history", actor_name.c_str());
}

void ProcessManager::ignore_history(const string &actor_name) {
    if (const auto it = process_logs.find(actor_name); it != process_logs.end()) {
        it->second.history_enabled = false;
        it->second.history.clear();
        return;
    }
    throw setup_error("Process {} not found to ignore history", actor_name.c_str());
}

void ProcessManager::discard_history(const string &actor_name) {
    if (const auto it = process_logs.find(actor_name); it != process_logs.end()) {
        it->second.history.clear();
        return;
    }
    throw setup_error("Process {} not found to discard history", actor_name.c_str());
}

void ProcessManager::wait_for(const string &actor_name, const string &pattern){
    if (const auto pit = processes.find(actor_name); pit == processes.end() || !pit->second) {
        throw runtime_error("Unknown process in wait_for: " + actor_name);
    }

    const auto actor_log = process_logs.find(actor_name);
    if (actor_log == process_logs.end()) {
        throw runtime_error("No logs for process in wait_for: " + actor_name);
    }

    ProcessLogs &logs = actor_log->second;
    logs.history_enabled = true;

    logs.wait.pattern = regex(pattern);
    logs.wait.active = true;
    logs.wait.matched = false;

    {  // first pass: check existing history
       // - in block because ss/line will be freed and don't waste memory
        stringstream ss(logs.history);
        string line;
        while (getline(ss, line)) {
            if (regex_search(line, logs.wait.pattern)) {
                logs.wait.matched = true;
                break;
            }
        }
        if (logs.wait.matched) {
            logs.history.clear();
            logs.wait.active = false;
            return;
        }
    }


    { // wait for new output to match
        unique_lock lock(wait_mutex);
        wait_cv.wait(lock, [&logs]{ return logs.wait.matched; });
    }

    logs.history.clear();
    logs.wait.active = false;
}

void ProcessManager::stop(const std::string &actor_name){
    using namespace std::chrono_literals;

    const auto it = processes.find(actor_name);
    if (it == processes.end() || !it->second) {
        log(LogLevel::WARNING,"Cant stop actor {}, no in Process manager", actor_name.c_str());
        return;
    }

    reproc::process &proc = *it->second;

    reproc::stop_actions operations{};
    //TODO add function for hard kill
    // operations.first  = { reproc::stop::terminate, reproc::milliseconds(3000) };
    operations.second = { reproc::stop::kill,      reproc::milliseconds(1000) };

    proc.stop(operations);
    processes.erase(it);
}

ProcessManager::~ProcessManager(){
    stop_all();
    combined_log.close();
    for(auto &entry: process_logs | views::values){
        if(entry.log.is_open()){ entry.log.close(); }
    }
}

void ProcessManager::stop_all(){
    for(auto &proc: processes | views::values){
        if(proc){
            reproc::stop_actions operations{};
            operations.first = {reproc::stop::terminate, reproc::milliseconds(1000)};
            operations.second = {reproc::stop::kill, reproc::milliseconds(1000)};
            proc->stop(operations);
        }
    }
    processes.clear();
}
