#include "system/ProcessManager.h"
#include <memory>
#include <system_error>
#include <map>
#include <ranges>
#include <regex>
#include <chrono>
#include <sstream>
#include "logger/error_log.h"
#include <thread>

namespace wpa3_tester{
    using namespace std;
    using namespace filesystem;
    using namespace chrono;

    void ProcessManager::handle_chunk(
        const shared_ptr<ManagedProcess>& mp,
        const string &process_name,
        const string &label,
        const string &data)
    {
        const string prefix =
            current_timestamp() + " [" + process_name + "] [" + label + "] ";

        stringstream ss(data);
        string line;

        while (getline(ss, line)) {
            if (line.empty()) continue;

            const string full_line = prefix + line;
            lock_guard lock(mtx_);
            if (combined_log.is_open()) write_log_line(combined_log, full_line);
            auto &logs = mp->logs;
            if (logs.log.is_open()) write_log_line(logs.log, full_line);

            if (logs.history_enabled) {logs.history += line;logs.history.push_back('\n');}

            if (logs.wait.active) {
                if (regex_search(line, logs.wait.pattern)) {
                    logs.wait.matched = true;

                    unique_lock signal_lock(wait_mutex);
                    wait_cv.notify_all();
                }
            }
        }
    }

    void ProcessManager::start_drain_for(const string &process_name,
                                          shared_ptr<ManagedProcess> mp) {
        if (!mp) return;

        mp->shutting_down = false;
        mp->drain_thread = thread([this, process_name, mp]() {

            uint8_t buffer[4096];
            while (!mp->shutting_down) {

                auto [events, ec] =
                    mp->proc->poll(reproc::event::out | reproc::event::err,
                                   reproc::milliseconds(100));

                if (ec == errc::timed_out)continue;
                if(ec){
                    if (ec == errc::broken_pipe ||
                    ec == errc::no_such_process) {

                    log(LogLevel::DEBUG,
                        "Drain thread for %s finished (normal exit): %s",
                        process_name.c_str(),
                        ec.message().c_str());
                } else {
                    log(LogLevel::ERROR,
                        "Drain thread for %s error: %s (code: %d)",
                        process_name.c_str(),
                        ec.message().c_str(),
                        ec.value());
                }

                break;
                }
                if (events & reproc::event::out) {
                    auto [n, read_ec] =
                        mp->proc->read(reproc::stream::out, buffer, sizeof(buffer));

                    if (!read_ec && n > 0) {
                        handle_chunk(mp,
                                     process_name,
                                     "stdout",
                                     string(reinterpret_cast<char *>(buffer), n));
                    }
                }

                if (events & reproc::event::err) {
                    auto [n, read_ec] =
                        mp->proc->read(reproc::stream::err, buffer, sizeof(buffer));

                    if (!read_ec && n > 0) {
                        handle_chunk(mp,
                                     process_name,
                                     "stderr",
                                     string(reinterpret_cast<char *>(buffer), n));
                    }
                }
            }
            cerr << "Drain thread exited for " << process_name << endl;
        });
    }


    ProcessManager::~ProcessManager() {
        stop_all();
        lock_guard lock(mtx_);
        if (combined_log.is_open())
            combined_log.close();
    }
    void ProcessManager::run(const string& process_name,
                         const vector<string> &cmd,
                         const path &working_dir)
    {
        auto mp = make_shared<ManagedProcess>();
        mp->proc = make_shared<reproc::process>();

        reproc::options options{};
        options.stop.first  = { reproc::stop::terminate, reproc::milliseconds(500) };
        options.stop.second = { reproc::stop::kill,      reproc::milliseconds(500) };
        options.redirect.parent = false;

        path log_dir = log_base_dir;
        path log_path = log_dir / (process_name + ".log");

        string wd_string; // need to be outside if, to be valid
        if (!working_dir.empty()) {
            wd_string = working_dir.string();
            options.working_directory = wd_string.c_str();
            log_path = working_dir / (process_name + ".log");
        }

        // Log command line FIRST for debugging
        string cmd_line;
        for (size_t i = 0; i < cmd.size(); ++i) {
            if (i) cmd_line += ' ';
            cmd_line += cmd[i];
        }
        log(LogLevel::DEBUG, "Starting process '%s': %s", process_name.c_str(), cmd_line.c_str());

        // Initialize logs BEFORE starting process
        auto &logs = mp->logs;
        logs.log.close();
        logs.log.open(log_path, ios::out | ios::trunc);
        logs.history.clear();

        if (!logs.log.is_open()) {
            log(LogLevel::ERROR, "Failed to open log for %s: %s", process_name.c_str(), log_path.string().c_str());
        }

        {
            lock_guard lock(mtx_);
            processes[process_name] = mp;
        }

        if (const auto ec = mp->proc->start(cmd, options)) {
            {
                lock_guard lock(mtx_);
                processes.erase(process_name);
            }
            throw runtime_error("Failed to start " + process_name + ": " + ec.message());
        }

        start_drain_for(process_name, mp);

        const string line = current_timestamp() + " [" + process_name + "] [cmd] " + cmd_line;
        if (combined_log.is_open()) {write_log_line(combined_log, line);}
        if (logs.log.is_open())     {write_log_line(logs.log, line);}
    }
    void ProcessManager::wait_for(const string &actor_name,
                              const string &pattern,
                              const seconds timeout)
    {
        shared_ptr<ManagedProcess> mp;

        {
            lock_guard lock(mtx_);
            auto it = processes.find(actor_name);
            if (it == processes.end() || !it->second) {
                throw runtime_error("Unknown process in wait_for: " + actor_name);
            }
            mp = it->second;
        }

        auto &logs = mp->logs;

        {
            lock_guard lock(mtx_);

            logs.history_enabled = true;
            logs.wait.pattern = regex(pattern);
            logs.wait.active = true;
            logs.wait.matched = false;

            // first pass – search history
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

        { // wait for match from drain thread with timeout
            unique_lock lock(wait_mutex);
            const bool matched = wait_cv.wait_for(lock, timeout, [&logs, mp] {
                return logs.wait.matched || mp->shutting_down.load();
            });

            // Check if process was stopped (shutting_down but not matched)
            if (mp->shutting_down.load() && !logs.wait.matched) {
                lock_guard log_lock(mtx_);
                logs.wait.active = false;
                logs.history_enabled = false;
                log(LogLevel::DEBUG, "wait_for for '%s' interrupted: process stopped", actor_name.c_str());
                return; // wait for ot matched if stop
            }

            if (!matched) {
                lock_guard log_lock(mtx_);
                logs.wait.active = false;
                throw timeout_err(
                    "Timeout waiting for pattern '%s' in process '%s' (timeout: %d seconds)",
                    pattern.c_str(), actor_name.c_str(), static_cast<int>(timeout.count()));
            }
        }

        lock_guard lock(mtx_);
        logs.history.clear();
        logs.wait.active = false;
    }

    void ProcessManager::stop(const string &process_name)
    {
        shared_ptr<ManagedProcess> mp;

        {
            lock_guard lock(mtx_);
            auto it = processes.find(process_name);
            if (it == processes.end())
                return;

            mp = it->second;

            // Clean up wait state and notify any waiting threads
            auto &logs = mp->logs;
            logs.wait.active = false;
            logs.wait.matched = false;
            logs.history_enabled = false;

            processes.erase(it);
        }

        // Notify all waiting threads that process is shutting down
        {
            unique_lock lock(wait_mutex);
            mp->shutting_down = true;
            wait_cv.notify_all();
        }

        mp->proc->close(reproc::stream::out);
        mp->proc->close(reproc::stream::err);

        reproc::stop_actions operations{};
        operations.first  = { reproc::stop::terminate, reproc::milliseconds(500) };
        operations.second = { reproc::stop::kill,      reproc::milliseconds(500) };

        mp->proc->stop(operations);

        // wait for drain thread
        if (mp->drain_thread.joinable())
            mp->drain_thread.join();
    }

    void ProcessManager::stop_all() {
        vector<string> process_names;
        {
            lock_guard lock(mtx_);
            process_names.reserve(processes.size());
            for (const auto &name : processes | views::keys) {
                process_names.push_back(name);
            }
        }

        for (const auto& name : process_names) {
            try {
                stop(name);
            } catch (const exception& e) {
                log(LogLevel::WARNING, "Error stopping process %s: %s", name.c_str(), e.what());
            }
        }

        log(LogLevel::DEBUG, "All processes stopped");
    }
}