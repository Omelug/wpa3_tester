#include "observer/observers.h"

#include "logger/log.h"
#include "system/utils.h"

namespace wpa3_tester::observer{
using namespace std;
using namespace filesystem;

path get_observer_folder(const RunStatus &rs, const string &observer_name){
	const path obs_dir = rs.run_folder()/"observer"/observer_name;
	error_code ec;
	create_public_dirs(obs_dir, ec);
	if(ec){
		log(LogLevel::ERROR, "Failed to create {} observer dir {}: {}", observer_name, obs_dir.string(), ec.message());
	}
	return obs_dir;
}

void add_nets_header(const RunStatus &rs, vector<string> &command, const string &src_name){
	if(!rs.config().at("actors").at(src_name).contains("netns")){ return; }
	if(const auto netns_node = rs.config().at("actors").at(src_name).at("netns"); !netns_node.is_null()){
		auto netns_client = netns_node.get<string>();
		command.insert(command.end(), {"ip", "netns", "exec", netns_client});
	}
}

void transform_to_relative(vector<LogTimePoint> &times, const LogTimePoint &start_time){
	if(times.empty()) return;
	const LogTimePoint t0 = start_time;
	for(auto &t: times){
		auto rel = t - t0;
		t = LogTimePoint(chrono::duration_cast<chrono::nanoseconds>(rel));
	}
}
}