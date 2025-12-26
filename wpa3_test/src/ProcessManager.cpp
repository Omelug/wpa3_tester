#include "ProcessManager.h"
#include <memory>
#include <system_error>
#include <map>
#include <iostream>
#include <regex>

using namespace std;

void ProcessManager::run(const string& name, vector<string> cmd) {
    auto proc = make_unique<reproc::process>();
    reproc::options options;
    options.stop.first = { reproc::stop::terminate, reproc::milliseconds(2000) };
    options.stop.second = { reproc::stop::kill, reproc::milliseconds(2000) };

    error_code ec = proc->start(cmd, options);
    if (ec) {
        throw runtime_error("Failed to start " + name + ": " + ec.message());
    }

    processes[name] = move(proc);
}

bool ProcessManager::wait_for(const string& name, const string& pattern) {
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
              	return make_error_code(errc::interrupted);
            }
        }
       	return error_code();
    };

    reproc::drain(*proc, sink, sink);

    return found;
}

ProcessManager::~ProcessManager() {
    stop_all();
}

void ProcessManager::stop_all() {
    for (auto& [name, proc] : processes) {
        if (proc) {
            reproc::stop_actions operations;
            operations.first = { reproc::stop::terminate, reproc::milliseconds(1000) };
            operations.second = { reproc::stop::kill, reproc::milliseconds(1000) };
            proc->stop(operations);
        }
    }
    processes.clear();
}
