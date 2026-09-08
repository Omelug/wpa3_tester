#include "observer/dmesg_wrapper.h"
#include "config/RunStatus.h"
#include "observer/observers.h"
#include <fstream>

namespace wpa3_tester::observer::dmesg{
using namespace std;

void start_dmesg(RunStatus &rs, const string &level){
	const string obs_folder = get_observer_folder(rs, "dmesg");
	vector<string> args = {"dmesg", "-W"};
	if(!level.empty()) args.push_back("--level=" + level);
	rs.process_manager.run("dmesg_log", args, {}, obs_folder);
}

vector<string> grep_log(const filesystem::path &log_file, const string &pattern) {
	vector<string> matches;
	ifstream f(log_file);
	string line;
	while (getline(f, line))
		if (line.find(pattern) != string::npos) matches.push_back(line);
	return matches;
}
}
