#include <filesystem>
#include "config/RunStatus.h"
#include "observer/observers.h"
#include "observer/tcpdump_wrapper.h"

#include "ex_program/external_actors/openwrt/OpenWrtConn.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::observer{
    using namespace std;
    using namespace filesystem;

    constexpr string program_name = "tcpdump";
    void start_tcpdump(RunStatus &rs, const string &actor_name, const string& filter) {
        const auto actor = rs.get_actor(actor_name);
        if(actor->conn != nullptr){
            start_tcpdump_remote(rs, actor_name, filter);
            return;
        }
        vector<string> command = {};
        add_nets(rs, command, actor_name);

        string pcap_path = get_observer_folder(rs, program_name) / (actor_name+"_capture.pcap");
        const optional<string> iface = rs.get_actor(actor_name)->str_con.at("sniff_iface");
        string iface_str;
        if(iface == nullopt){
            iface_str = rs.get_actor(actor_name)["iface"];
        } else{
            iface_str = MONITOR_IFACE_PREFIX + iface.value();
        }

        command.insert(command.end(), {
            "tcpdump", "-i", iface_str,
            "-w", pcap_path
        });
        if (!filter.empty()) { command.push_back("-f"); command.push_back(filter); }

        rs.process_manager.run(actor_name+"_cap", command, get_observer_folder(rs, program_name));
    }

    void start_tcpdump_remote(RunStatus &rs, const string &actor_name, const string& filter) {
        const auto& actor = rs.get_actor(actor_name);
        const string remote_pcap = "/overlay/"+actor_name+"_capture.pcap";
        const string iface_str = actor["iface"];

        string tcpdump_cmd = "tcpdump -i "+iface_str+" -p -w "+remote_pcap;
        if (!filter.empty()) tcpdump_cmd += " "+filter;

        const vector<string> command = {
            "sshpass", "-p", actor["ssh_password"],
            "ssh", "-o", "StrictHostKeyChecking=no",
            actor["ssh_user"]+"@"+actor["whitebox_ip"],
            tcpdump_cmd
        };
        const string local_pcap  = get_observer_folder(rs, program_name) / (actor_name+"_capture.pcap");
        rs.process_manager.run(actor_name+"_cap", command, get_observer_folder(rs, program_name));
        rs.process_manager.on_stop(actor_name+"_cap", [remote_pcap, local_pcap, actor]() {
           const vector<string> scp_cmd = {"sshpass", "-p", actor["ssh_password"], "scp", "-O", actor["ssh_user"] +"@"+actor["whitebox_ip"]+":"+remote_pcap, local_pcap};
           hw_capabilities::run_cmd(scp_cmd);
           actor->conn->exec("rm "+remote_pcap);  // cleanup
       });
    }
}
