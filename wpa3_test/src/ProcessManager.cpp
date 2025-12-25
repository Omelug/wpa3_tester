#include "ProcessManager.h"
#include <memory>
#include <system_error>
#include <map>
#include <iostream>
#include <regex>

using namespace std;

void ProcessManager::run(const std::string& name, std::vector<std::string> cmd) {
    auto proc = std::make_unique<reproc::process>();
    reproc::options options;
    options.stop.first = { reproc::stop::terminate, reproc::milliseconds(2000) };
    options.stop.second = { reproc::stop::kill, reproc::milliseconds(2000) };

    std::error_code ec = proc->start(cmd, options);
    if (ec) {
        throw std::runtime_error("Failed to start " + name + ": " + ec.message());
    }

    processes[name] = std::move(proc);
}

bool ProcessManager::wait_for(const string& name, string pattern, int timeout_ms) {
    auto& proc = processes.at(name);
    string accumulator;
    regex re(pattern);
    bool found = false;

    auto sink = [&](reproc::stream stream, const uint8_t *buffer, size_t size) {
        accumulator.append(reinterpret_cast<const char*>(buffer), size);

        size_t pos;
        // all full lines
        while ((pos = accumulator.find('\n')) != string::npos) {
            string line = accumulator.substr(0, pos);
            accumulator.erase(0, pos + 1);

            if (regex_search(line, re)) {
                found = true;
              	return std::make_error_code(std::errc::interrupted);
            }
        }
       	return std::error_code();
    };

    reproc::drain(*proc, sink, sink);

    return found;
}

ProcessManager::~ProcessManager() {
    stop_all(); // ensure processes are terminated when manager is destroyed
}

void ProcessManager::stop_all() {
    for (auto& [name, proc] : processes) {
        if (proc) {
            // Nemusíme se ptát, jestli běží, stop() to vyřeší za nás
            reproc::stop_actions operations;
            operations.first = { reproc::stop::terminate, reproc::milliseconds(1000) };
            operations.second = { reproc::stop::kill, reproc::milliseconds(1000) };

            // Ignorujeme případnou chybu, pokud proces už neexistoval
            proc->stop(operations);
        }
    }
    processes.clear();
}
