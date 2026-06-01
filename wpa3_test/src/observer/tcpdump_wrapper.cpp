#include "observer/tcpdump_wrapper.h"

#include <filesystem>

#include "config/RunStatus.h"
#include "ex_program/external_actors/openwrt/OpenWrtConn.h"
#include "observer/observers.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"

namespace wpa3_tester::observer{
using namespace std;
using namespace filesystem;

constexpr string program_name = "tcpdump";

void start_tcpdump_remote(RunStatus &rs, const string &actor_name, const string &filter){
	const auto &actor = rs.get_actor(actor_name);
	const string remote_pcap = "/overlay/" + actor_name + "_capture.pcap";
	const string iface_str = actor.get(SK::iface);

	string tcpdump_cmd = "tcpdump -i " + iface_str + " -p -w " + remote_pcap;
	if(!filter.empty()) tcpdump_cmd += " " + filter;

	const vector<string> command = {
		"sshpass", "-p", actor.get(SK::ssh_password), "ssh", "-o", "StrictHostKeyChecking=no",
		actor.get(SK::ssh_user) + "@" + actor.get(SK::whitebox_ip), tcpdump_cmd
	};
	const string local_pcap = get_observer_folder(rs, program_name) / (actor_name + "_capture.pcap");
	rs.process_manager.run(actor_name + "_cap", command, get_observer_folder(rs, program_name));
	rs.process_manager.after_stop(actor_name + "_cap", [remote_pcap, local_pcap, actor](){
		const vector<string> scp_cmd = {
			"sshpass", "-p", actor.get(SK::ssh_password), "scp", "-O",
			actor.get(SK::ssh_user) + "@" + actor.get(SK::whitebox_ip) + ":" + remote_pcap, local_pcap
		};
		hw_capabilities::run_cmd(scp_cmd);
		if(exists(local_pcap)) set_public_perms(local_pcap);
	});

	actor->conn->on_disconnect([remote_pcap, actor](){
		actor->conn->exec("rm " + remote_pcap);
	});
}

void start_tcpdump(RunStatus &rs, const string &actor_name, const string &filter){
	const auto actor = rs.get_actor(actor_name);
	if(actor->conn != nullptr){
		start_tcpdump_remote(rs, actor_name, filter);
		return;
	}

	const auto obs_folder = get_observer_folder(rs, program_name);
	const optional<string>& sniff = actor[SK::sniff_iface];
	const string iface = sniff ? MONITOR_IFACE_PREFIX + *sniff : actor.get(SK::iface);

	vector<string> command;
	add_nets_header(rs, command, actor_name);
	path pcap_path = obs_folder / (actor_name + "_capture.pcap");
	command.insert(command.end(), {"tcpdump", "-i", iface, "-w", pcap_path});
	if(!filter.empty()) command.insert(command.end(), {"-f", filter});

	rs.process_manager.run(actor_name + "_cap", command, obs_folder);
	rs.process_manager.after_stop(actor_name + "_cap", [pcap_path](){
		if (exists(pcap_path)) set_public_perms(pcap_path);
	});
}
}
