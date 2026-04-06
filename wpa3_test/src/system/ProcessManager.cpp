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

    void ProcessManager::run_dummy(const string& process_name) {
        const auto mp = make_shared<ManagedProcess>();
        mp->proc = nullptr;
        mp->logs.history_enabled = true;

        const path log_path = log_base_dir / (process_name + ".log");
        mp->logs.log.open(log_path, ios::out | ios::trunc);

        lock_guard lock(logger_mtx);
        processes[process_name] = mp;
    }

    void ProcessManager::handle_chunk(
    //const shared_ptr<ManagedProcess>& mp,
    const string &process_name,
    const string &label,
    const string &data)
    {
        bool should_notify = false;
        {
            lock_guard lock(logger_mtx);
            const auto it = processes.find(process_name);
            if (it == processes.end() || !it->second) {
                log(LogLevel::WARNING, "handle_chunk: process not found: " + process_name);
                return;
            }
            const auto mp = it->second;
            auto &incomplete = mp->logs.buffers[label];
            incomplete += data;

            size_t pos;
            while ((pos = incomplete.find('\n')) != string::npos) {
                string line = incomplete.substr(0, pos);
                incomplete.erase(0, pos + 1);

                if (line.empty()) continue;

                const string prefix = current_timestamp() + " [" + process_name + "] [" + label + "] ";
                const string full_line = prefix + line;

                if (combined_log.is_open()) write_log_line(combined_log, full_line);
                if (mp->logs.log.is_open()) write_log_line(mp->logs.log, full_line);
                if (mp->logs.history_enabled) mp->logs.history += line + "\n";

                if (mp->logs.wait.pattern && regex_search(line, *mp->logs.wait.pattern)) {
                    log(LogLevel::DEBUG, "MATCH " + process_name + " " + line);
                    mp->logs.wait.matched = true;
                    should_notify = true;
                }
            }
        } // logger_mtx

        if (should_notify)
            wait_cv.notify_all();
    }

    void ProcessManager::start_drain_for(const string &process_name, const shared_ptr<ManagedProcess>& mp) {
        if (!mp) return;
        mp->shutting_down = false;
        mp->drain_thread = thread([this, process_name, mp]() {
            uint8_t buffer[4096];

            struct StreamInfo { reproc::stream stream; const char* label; int event; };
            constexpr StreamInfo streams[] = {
                    { reproc::stream::out, "stdout", reproc::event::out },
                    { reproc::stream::err, "stderr", reproc::event::err }
                };

            while (true){
                //log(LogLevel::DEBUG, "poll start "+process_name);
                auto [events, ec] = mp->proc->poll(reproc::event::out | reproc::event::err | reproc::event::exit, reproc::milliseconds(100));
                //log(LogLevel::DEBUG, "poll end "+process_name);
                if (mp->shutting_down) break;
                if (ec == errc::timed_out) continue;
                if(ec){
                    if (ec == errc::broken_pipe ||ec == errc::no_such_process) {
                        log(LogLevel::DEBUG, "Drain thread for "+process_name+" finished (normal exit): "+ec.message());
                    } else {
                        log(LogLevel::ERROR, "Drain thread for %s error: %s (code: %d)",
                            process_name.c_str(), ec.message().c_str(), ec.value());
                    }
                    break;
                }
                for (const auto &s : streams) {
                    if (!(events & s.event)) continue;

                    while (true) {
                        auto [n, read_ec] = mp->proc->read(s.stream, buffer, sizeof(buffer));

                        if (read_ec){
                            if (read_ec == errc::resource_unavailable_try_again ||
                                read_ec == errc::operation_would_block){
                                break;
                            }
                            break;
                        }
                        if (n == 0) break;
                        handle_chunk(process_name, s.label, string(reinterpret_cast<char *>(buffer), n));
                    }
                }
            }
            mp->proc->close(reproc::stream::in);

            // Flush anything left in the pipe after shutting_down is set
            log(LogLevel::DEBUG, "flush start "+process_name);
            for (const auto &s : streams) {
                while (true) {
                    auto [events, poll_ec] = mp->proc->poll(s.event, reproc::milliseconds(50));
                    if (poll_ec || !(events & s.event)) break;  // no data or error

                    auto [n, read_ec] = mp->proc->read(s.stream, buffer, sizeof(buffer));
                    if (read_ec || n == 0) break;
                    handle_chunk(process_name, s.label, string(reinterpret_cast<char *>(buffer), n));
                }
            }

            log(LogLevel::DEBUG, "flush done "+process_name);
            log(LogLevel::DEBUG, "Drain thread exited for "+process_name);
        });
    }


    ProcessManager::~ProcessManager() {
        stop_all();
        lock_guard lock(logger_mtx);
        if (combined_log.is_open()) combined_log.close();
    }

    void ProcessManager::run(const string& process_name,
                         const vector<string> &cmd,
                         const path &working_dir,
                         const path &logging_dir)
    {
        //log(LogLevel::DEBUG, "PROCESS RUN: "+ process_name);
        auto mp = make_shared<ManagedProcess>();
        mp->proc = make_shared<reproc::process>();

        reproc::options options{};
        options.stop.first  = { reproc::stop::terminate, reproc::milliseconds(500) };
        options.stop.second = { reproc::stop::kill,      reproc::milliseconds(500) };
        options.redirect.parent = false;

        path log_dir = log_base_dir;

        string wd_string;
        if (!working_dir.empty()) {
            wd_string = working_dir.string();
            options.working_directory = wd_string.c_str();
        }
        if (!logging_dir.empty()) {log_dir= logging_dir;}
        path log_path = log_dir / (process_name+".log");

        string cmd_debug;
        for (const auto& s : cmd) cmd_debug += "[" + s + "] ";
        log(LogLevel::DEBUG, "Full command: %s", cmd_debug.c_str());

        // Log command line FIRST for debugging
        string cmd_line;
        for (size_t i = 0; i < cmd.size(); ++i) {if (i) cmd_line += ' ';cmd_line += cmd[i];}
        log(LogLevel::DEBUG, "Starting process '"+process_name+"': "+cmd_line);

        // Initialize logs BEFORE starting process
        auto &logs = mp->logs;
        logs.log.close();
        logs.log.open(log_path, ios::out | ios::trunc);
        logs.history.clear();
        logs.history_enabled = true;


        if (!logs.log.is_open()) { throw config_err("Failed to open log for "+process_name+": "+log_path.string());}

        {
            lock_guard lock(logger_mtx);
            processes[process_name] = mp;
        }

        if (const auto ec = mp->proc->start(cmd, options)) {
            {
                lock_guard lock(logger_mtx);
                processes.erase(process_name);
            }
            throw runtime_error("Failed to start "+process_name+": "+ec.message());
        }

        start_drain_for(process_name, mp);

        const string line = current_timestamp()+" ["+process_name+"] [cmd] "+cmd_line;
        lock_guard lock(logger_mtx);
        if (combined_log.is_open()) {write_log_line(combined_log, line);}
        if (logs.log.is_open())     {write_log_line(logs.log, line);}
    }

    bool ProcessManager::wait_for(const string &actor_name,
                                  const string &pattern,
                                  const seconds timeout,
                                  const bool throw_err)
    {
        shared_ptr<ManagedProcess> mp;
        log(LogLevel::DEBUG, "WAIT pattern:"+ pattern);
        {
            lock_guard lock(logger_mtx);
            const auto proc_iter = processes.find(actor_name);
            if (proc_iter == processes.end() || !proc_iter->second) {
                throw runtime_error("Unknown process in wait_for: "+actor_name);
            }
            mp = proc_iter->second;
            auto &logs = mp->logs;

            logs.wait.pattern = regex(pattern);
            logs.wait.matched = false;

            // first pass – search history
            stringstream ss(logs.history);
            string line;
            while (getline(ss, line)) {
                if (regex_search(line, *logs.wait.pattern)) {
                    log(LogLevel::DEBUG, "MATCH without history " + actor_name + " " + line);
                    logs.wait.matched = true;
                    break;
                }
            }

            if (logs.wait.matched) {
                logs.history.clear(); //FIXME only until matched
                logs.wait.pattern = nullopt;
                return true;
            }
        }

        { // wait for match from drain thread with timeout
            unique_lock lock(wait_mutex);
            auto &logs = mp->logs;
            const bool matched = wait_cv.wait_for(lock, timeout, [&logs, mp, pattern] {
                //log(LogLevel::DEBUG, "WAIT_CHECK pattern: "+ pattern);
                // regex matched or shutting down -> continue
                return logs.wait.matched || mp->shutting_down.load();
            });


            // Check if process was stopped (shutting_down but not matched)
            if (mp->shutting_down.load() && !logs.wait.matched) {
                lock_guard data_lock(logger_mtx);
                logs.wait.pattern = nullopt;
                logs.history_enabled = false;
                log(LogLevel::DEBUG, "wait_for for '"+actor_name+"' interrupted: process stopped");
                return false; // wait for ot matched if stop
            }

            if (!matched) { // !matched = time interrupted
                lock_guard data_lock(logger_mtx);
                logs.wait.pattern = nullopt;
                if(throw_err){
                    throw timeout_err(
                        "Timeout waiting for pattern '%s' in process '%s' (timeout: %d seconds)",
                        pattern.c_str(), actor_name.c_str(), static_cast<int>(timeout.count()));
                }
                return false;
            }

            lock_guard data_lock(logger_mtx);
            logs.history.clear();
            logs.wait.pattern = nullopt;
        }
        return true;
    }

    void ProcessManager::stop(const string &process_name){
        //log(LogLevel::DEBUG, "stop() called for "+process_name);
        shared_ptr<ManagedProcess> mp;
        {
            lock_guard lock(logger_mtx);
            const auto proc_iter = processes.find(process_name);
            if (proc_iter == processes.end()) return;

            mp = proc_iter->second;

            // Clean up wait state and notify any waiting threads
            mp->logs.history_enabled = false;
            mp->shutting_down = true;
            processes.erase(proc_iter);
        }
        //log(LogLevel::DEBUG, "shutting_down set for "+process_name);
        wait_cv.notify_all();

        reproc::stop_actions operations{};
        operations.first  = { reproc::stop::terminate, reproc::milliseconds(500) };
        operations.second = { reproc::stop::kill,      reproc::milliseconds(500) };

        if (mp->proc){
            //log(LogLevel::DEBUG, "terminate() calling");
            mp->proc->terminate();
            //log(LogLevel::DEBUG, "terminate() done");
            mp->proc->kill();
            //log(LogLevel::DEBUG, "kill() done");
        }
        //log(LogLevel::DEBUG, "joining...");
        if (mp->drain_thread.joinable()) mp->drain_thread.join();
        //log(LogLevel::DEBUG, "join done");

        // Call on_stop callback if registered
        if (mp->before_stop_callback){
            try {
                mp->before_stop_callback();
            } catch (const exception& e) {
                log(LogLevel::WARNING, "Error in on_stop callback for "+process_name +":"+e.what());
            }
        }

        if (mp->proc){ mp->proc->stop(operations);}
        log(LogLevel::DEBUG, "proc->stop done for "+process_name);

        // Call on_stop callback if registered
        if (mp->after_stop_callback){
            try {
                mp->after_stop_callback();
            } catch (const exception& e) {
                log(LogLevel::WARNING, "Error in on_stop callback for "+process_name +":"+e.what());
            }
        }
    }

    void ProcessManager::stop_all() {

        vector<string> process_names;
        {
            lock_guard lock(logger_mtx);
            process_names.reserve(processes.size());
            for (const auto &name : processes | views::keys) {process_names.push_back(name);}
        }

        for (const auto& name : process_names) {
            try {
                stop(name);
            } catch (const exception& e) {
                log(LogLevel::WARNING, "Error stopping process "+name+": "+e.what());
            }
        }
        log(LogLevel::DEBUG, "All processes stopped");
    }

    //TODO add test
    void ProcessManager::before_stop(const string& process_name, const function<void()> &callback) {
        lock_guard lock(logger_mtx);
        const auto proc_iter = processes.find(process_name);
        if (proc_iter != processes.end() && proc_iter->second) {
            proc_iter->second->before_stop_callback = callback;
        }
    }
    void ProcessManager::after_stop(const string& process_name, const function<void()> &callback) {
        lock_guard lock(logger_mtx);
        const auto proc_iter = processes.find(process_name);
        if (proc_iter != processes.end() && proc_iter->second) {
            proc_iter->second->after_stop_callback = callback;
        }
    }
}