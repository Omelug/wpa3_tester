#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <condition_variable>
#include <regex>
#include <reproc++/reproc.hpp>

class ProcessManager{
public:
    std::map<std::string, std::unique_ptr<reproc::process>> processes;
    std::filesystem::path log_base_dir;
    std::ofstream combined_log;

    struct WaitListener {
        std::regex pattern{};
        bool active = false;
        bool matched = false;
    };

    struct ProcessLogs {
        std::ofstream log;
        std::string   history;
        bool          history_enabled = false;
        WaitListener  wait;
    };
    std::map<std::string, ProcessLogs> process_logs;
    std::mutex wait_mutex;
    std::condition_variable wait_cv;

    static void write_log_line(std::ofstream &os, const std::string &line);

private:
    bool draining_started = false;
    void start_global_drain();

public:
    ProcessManager() = default;
    ~ProcessManager();

    ProcessManager(const ProcessManager&) = delete;
    ProcessManager& operator=(const ProcessManager&) = delete;

    void init_logging(const std::string& run_folder);

    void run(const std::string& name, const std::vector<std::string> &cmd);
    void start_drain_for(const std::string &proc_name);
    void allow_history(const std::string &name);
    void ignore_history(const std::string &name);
    void discard_history(const std::string &name);

    void wait_for(const std::string &name, const std::string &pattern);

    // After stop (Ctrl + C or critical error)
    void stop_all();
};