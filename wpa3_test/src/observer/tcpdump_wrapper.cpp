#include <filesystem>
#include "config/RunStatus.h"
#include "observer/observers.h"
#include "observer/tcpdump_wrapper.h"
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>

#include "ex_program/external_actors/openwrt/OpenWrtConn.h"

namespace wpa3_tester::observer{
    using namespace std;
    using namespace filesystem;

    constexpr string program_name = "tcpdump";
    void start_tcpdump(RunStatus &run_status, const string &node_name, const string& filter) {
        vector<string> command = {"sudo"};
        add_nets(run_status, command, node_name);

        string pcap_path = get_observer_folder(run_status, program_name) / (node_name + "_capture.pcap");
        const optional<string> iface = run_status.get_actor(node_name).str_con.at("sniff_iface");
        string iface_str;
        if (iface == nullopt) {
            iface_str = run_status.get_actor(node_name)["iface"];
        } else {
            iface_str = MONITOR_IFACE_PREFIX + iface.value();
        }

        command.insert(command.end(), {
            "tcpdump", "-i", iface_str,
            "-p",
            "-w", pcap_path,
            "-f", filter,
        });

        run_status.process_manager.run(node_name + "_cap", command, get_observer_folder(run_status, program_name));
    }

    void start_tcpdump_remote(RunStatus &run_status, const string &actor_name, const string& filter) {
        /*const auto& actor = run_status.get_actor(actor_name);
        // not /tmp so it will be valid after reboot (for failed tests) / DoS attacks
        const string remote_pcap = "/overlay/" + actor_name + "_capture.pcap";
        const string local_pcap  = get_observer_folder(run_status, program_name) / (actor_name + "_capture.pcap");

        const string iface_str = actor["iface"];

        string cmd = "tcpdump -i " + iface_str + " -p -w " + remote_pcap;
        if (!filter.empty()) cmd += " " + filter;
        cmd += " &";  // background

        // run via SSH
        auto conn = run_status.get_or_create_connection(actor_name);
        conn.exec(cmd);

        // register cleanup + download on stop
        run_status.process_manager.on_stop(actor_name + "_cap", [&conn, remote_pcap, local_pcap, actor_name]() {
            conn.exec("kill $(pgrep tcpdump)");
            // scp download
            reproc::process scp;
            scp.start({"scp", conn. "@" + conn.host + ":" + remote_pcap, local_pcap});
            scp.wait(reproc::infinite);
            conn.exec("rm " + remote_pcap);  // cleanup
        });*/
    }
}
