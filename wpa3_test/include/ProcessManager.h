#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <filesystem>
#include <fstream>
#include <reproc++/reproc.hpp>
#include <reproc++/drain.hpp>

class ProcessManager{
private:
    std::map<std::string, std::unique_ptr<reproc::process>> processes;
    std::filesystem::path log_base_dir;
    std::ofstream combined_log;

public:
    ProcessManager() = default;
    ~ProcessManager();

    ProcessManager(const ProcessManager&) = delete;
    ProcessManager& operator=(const ProcessManager&) = delete;

    void init_logging(const std::string& run_folder);

    void run(const std::string& name, const std::vector<std::string> &cmd);
    void wait_for(const std::string &name, const std::string &pattern) const;
    void stop_all();
};