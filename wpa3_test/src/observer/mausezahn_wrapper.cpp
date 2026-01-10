#pragma once
#include <filesystem>
#include "config/RunStatus.h"
#include "observer/observers.h"

namespace wpa3_tester::observer{
    using namespace std;
    using namespace filesystem;
    constexpr string program_name = "mausezahn";
    void start_musezahn(RunStatus& run_status, const string &actor_name, const string &src_name, const string &dst_name){
        vector<string> command = {"sudo"};
        add_nets(run_status,command, src_name);

        command.insert(command.end(), {
            program_name, run_status.get_actor("client")["iface"],
            "-t", "udp", "sp=1234,dp=5201",
            "-A",  run_status.config["actors"][src_name]["ip_addr"].get<string>(),
            "-B",  run_status.config["actors"][dst_name]["ip_addr"].get<string>(),
            "-p", "1250",  // 1250 bytes packet
            "-d", "1m",    // 1 millisecond
            "-c", "0"      // not time limited
        });
        run_status.process_manager.run(actor_name, command, get_observer_folder(run_status, program_name));
    };
}

