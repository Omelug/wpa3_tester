#include "observer/dmesg_wrapper.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "observer/observers.h"
#include <filesystem>
#include <fstream>

namespace wpa3_tester::observer::dmesg{
using namespace std;
using namespace filesystem;

void start_dmesg(RunStatus &rs, const string &observer_name, const string &level, const string &actor_name){
	const string obs_folder = get_observer_folder(rs, "dmesg");

	if(!actor_name.empty()){
		const auto actor = rs.get_actor(actor_name);
		if(actor->conn != nullptr){
			const string remote_log = "/tmp/dmesg_" + observer_name + ".log";
			const string pid_file = remote_log + ".pid";
			// BusyBox dmesg (OpenWrt) has no -W; fall back to polling with -c
			string cmd = "( dmesg -W";
			if(!level.empty()) cmd += " --level=" + level;
			cmd += " 2>/dev/null || while true; do dmesg -c >> " + remote_log + " 2>&1; sleep 1; done )";
			cmd += " >> " + remote_log + " 2>&1 & echo $! > " + pid_file;
			actor->conn->exec(cmd, false);
			const path local_log = path(obs_folder) / (observer_name + ".log");
			actor->conn->on_disconnect([remote_log, local_log, actor, pid_file](){
				actor->conn->exec("kill $(cat " + pid_file + ") 2>/dev/null; rm -f " + pid_file);
				actor->conn->download_file(remote_log, local_log);
				actor->conn->exec("rm -f " + remote_log);
			});
			return;
		}
	}

	vector<string> args = {"dmesg", "-W"};
	if(!level.empty()) args.push_back("--level=" + level);
	rs.process_manager.run(observer_name, args, {}, obs_folder);
}

vector<string> grep_log(const path &log_file, const string &pattern) {
	vector<string> matches;
	ifstream f(log_file);
	string line;
	while (getline(f, line))
		if (line.find(pattern) != string::npos) matches.push_back(line);
	return matches;
}
}
