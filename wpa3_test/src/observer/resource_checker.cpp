#include "observer/resource_checker.h"
#include <filesystem>
#include <vector>
#include <string>
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "observer/observers.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::observer {
    using namespace std;
    using namespace filesystem;
    const string program_name = "resource_checker";

    void start_resource_monitoring(RunStatus &rs, const string &actor_name, const int interval_sec) {
        const auto actor = rs.get_actor(actor_name);

        if (actor->conn != nullptr) {
            start_resource_monitoring_remote(rs, actor_name, interval_sec);
            return;
        }

        const int target_pid = rs.process_manager.get_pid(actor_name);
        const string log_dir = get_observer_folder(rs, program_name);

        const vector<string> command = {
            "pidstat",
            //"-T", "CHILD",
            "-h",
            "-p", to_string(target_pid),
            "-u", // cpu statistic
            "-r", // ram statistics
            to_string(interval_sec) // interval
        };
        rs.process_manager.run(actor_name + "_res", command, get_observer_folder(rs, program_name), log_dir);
    }

    void start_resource_monitoring_remote(RunStatus &rs, const string &actor_name, int interval_sec) {
        const auto& actor = rs.get_actor(actor_name);
        const string remote_log = "/tmp/" + actor_name + "_resources.log";
        const string local_log = get_observer_folder(rs, program_name) / (actor_name + "_resources.log");

        const string top_cmd = "top -b -d " + to_string(interval_sec) + " > " + remote_log;
        const vector<string> ssh_command = {
            "sshpass", "-p", actor["ssh_password"],
            "ssh", "-o", "StrictHostKeyChecking=no",
            actor["ssh_user"] + "@" + actor["whitebox_ip"],
            top_cmd
        };

        rs.process_manager.run(actor_name + "_res", ssh_command, get_observer_folder(rs, program_name));
        rs.process_manager.on_stop(actor_name + "_res", [remote_log, local_log, actor]() {
            const vector<string> scp_cmd = {
                "sshpass", "-p", actor["ssh_password"],
                "scp", "-O",
                actor["ssh_user"] + "@" + actor["whitebox_ip"] + ":" + remote_log,
                local_log
            };
            hw_capabilities::run_cmd(scp_cmd);
            actor->conn->exec("rm " + remote_log);
        });
    }
}
