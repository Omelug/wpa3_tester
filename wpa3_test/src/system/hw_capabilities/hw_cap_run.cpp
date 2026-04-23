#include <cstdlib>
#include <string>
#include <unistd.h>
#include <vector>
#include <sys/types.h>
#include <sys/wait.h>
#include <random>
#include <reproc++/drain.hpp>
#include <reproc++/reproc.hpp>

#include "system/hw_capabilities.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"

namespace wpa3_tester{
using namespace std;
using namespace filesystem;

void hw_capabilities::run_in(const string &cmd, const path &cwd = current_path()){
    const string full_cmd = "cd " + cwd.string() + " && " + cmd;
    if(system(full_cmd.c_str()) != 0){
        throw runtime_error("Command failed: " + cmd);
    }
}

int hw_capabilities::run_cmd(const vector<string> &argv, const optional<string> &netns){
    if(argv.empty()) return -1;

    // prepend ip netns exec if netns is set
    vector<string> full_argv;
    if(netns.has_value()){
        full_argv.reserve(argv.size() + 4);
        full_argv.emplace_back("ip");
        full_argv.emplace_back("netns");
        full_argv.emplace_back("exec");
        full_argv.push_back(*netns);
        full_argv.insert(full_argv.end(), argv.begin(), argv.end());
    } else{
        full_argv = argv;
    }

    vector<char *> args;
    args.reserve(full_argv.size() + 1);
    for(auto &s: full_argv){ args.push_back(const_cast<char *>(s.c_str())); }
    args.push_back(nullptr);

    reproc::process proc;
    reproc::options options;
    options.redirect.parent = true;
    options.redirect.out.type = reproc::redirect::parent;
    options.redirect.err.type = reproc::redirect::parent;

    if(const error_code ec = proc.start(full_argv, options)){
        log(LogLevel::ERROR, "Failed to start " + full_argv[0] + " " + ec.message());
        return -1;
    }

    auto [status, wait_ec] = proc.wait(reproc::infinite);
    this_thread::sleep_for(chrono::milliseconds(100)); //FIXME
    if(wait_ec){
        log(LogLevel::ERROR, "Wait failed: " + wait_ec.message());
        return -1;
    }
    if(status != 0){
        string command_str;
        for(const auto &arg: full_argv){
            command_str += arg + " ";
        }

        log(LogLevel::ERROR, "Command failed! Status: %d | Full command: %s",
            status, command_str.c_str());
        return -1;
    }
    return status;
}

string hw_capabilities::run_cmd_output(const vector<string> &argv){
    if(argv.empty()) return {};

    reproc::process proc;
    reproc::options options;

    options.redirect.out.type = reproc::redirect::pipe;

    error_code ec = proc.start(argv, options);
    if(ec){ return {}; }

    string output_str;
    reproc::sink::string sink_obj(output_str);

    ec = reproc::drain(proc, sink_obj, reproc::sink::null);
    if(ec){ return {}; }

    auto [status, wait_ec] = proc.wait(reproc::infinite);
    if(wait_ec){ return {}; }
    return output_str;
}

// ---------------- exec -. errors

void hw_capabilities::exec(const vector<string> &cmd, const bool check){
    string full;
    for(auto &s: cmd) full += s + " ";
    const int ret = system(full.c_str());
    if(check && ret != 0) throw runtime_error("Command failed: " + full);
}
}