#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <filesystem>
#include <fstream>
#include <reproc++/reproc.hpp>

class ProcessManager{
    std::map<std::string, std::unique_ptr<reproc::process>> processes;
    std::filesystem::path log_base_dir;
    std::ofstream combined_log;

    struct ProcessLogs {
        std::ofstream log;
        std::string   history;
        bool          history_enabled = false;
    };
    std::map<std::string, ProcessLogs> process_logs;
    static void write_log_line(std::ofstream &os, const std::string &line);

    bool draining_started = false;
    void start_global_drain();

public:
    ProcessManager() = default;
    ~ProcessManager();

    ProcessManager(const ProcessManager&) = delete;
    ProcessManager& operator=(const ProcessManager&) = delete;

    void init_logging(const std::string& run_folder);

    void run(const std::string& name, const std::vector<std::string> &cmd);
    void allow_history(const std::string &name);
    void ignore_history(const std::string &name);
    void discard_history(const std::string &name);

    void wait_for(const std::string &name, const std::string &pattern);

    void stop_all();
};