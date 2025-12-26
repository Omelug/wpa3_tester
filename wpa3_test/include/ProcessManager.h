#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <reproc++/reproc.hpp>
#include <reproc++/drain.hpp>

class ProcessManager{
private:
    std::map<std::string, std::unique_ptr<reproc::process>> processes;
public:
    ProcessManager() = default;
    ~ProcessManager();

    ProcessManager(const ProcessManager&) = delete;
    ProcessManager& operator=(const ProcessManager&) = delete;

    void run(const std::string& name, const std::vector<std::string> &cmd);
    void wait_for(const std::string &name, const std::string &pattern) const;
    void stop_all();
};