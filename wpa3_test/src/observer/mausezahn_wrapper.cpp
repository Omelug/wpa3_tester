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
            "-d", "1m",    // 1 millisecond
            "-c", "0",      // not time limited
            "-p", "1250",  // 1250 bytes packet
            "-t", "udp", "sp=1234,dp=5201",
            "-a",  run_status.get_actor(src_name)["mac"],
            "-b",  run_status.get_actor(dst_name)["mac"],
            "-P", "PAYLOAD"
        });
        run_status.process_manager.run(actor_name, command, get_observer_folder(run_status, program_name));
    };
}

