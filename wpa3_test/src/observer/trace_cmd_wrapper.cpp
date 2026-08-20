#include "observer/trace_cmd_wrapper.h"
#include <filesystem>
#include <string>
#include <vector>
#include "config/RunStatus.h"
#include "observer/observers.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"

namespace wpa3_tester::observer::trace_cmd{
using namespace std;
using namespace filesystem;

const string program_name = "trace_cmd";

void start_trace_cmd(RunStatus &rs, const string &actor_name, const vector<string> &events){
	const path obs_folder = get_observer_folder(rs, program_name);
	const path dat_path   = obs_folder / (actor_name + "_trace.dat");
	const path txt_path   = obs_folder / (actor_name + "_trace.txt");

	vector<string> command = {"trace-cmd", "record", "-o", dat_path.string()};
	for(const auto &e: events){ command.push_back("-e"); command.push_back(e); }

	rs.process_manager.run(actor_name + "_trace", command, obs_folder);
	rs.process_manager.after_stop(actor_name + "_trace", [dat_path, txt_path](){
		// convert binary trace to human-readable; shell needed for stdout redirect
		hw_capabilities::run_cmd(
			{"sh", "-c", "trace-cmd report -i " + dat_path.string() + " > " + txt_path.string()}
		);
		if(exists(dat_path)) set_public_perms(dat_path);
		if(exists(txt_path)) set_public_perms(txt_path);
	});
}

void start_dmesg(RunStatus &rs, const string &actor_name){
	const string obs_folder = get_observer_folder(rs, "dmesg");
	// dmesg -W streams new messages; process stdout is captured by logging_dir
	rs.process_manager.run(actor_name + "_dmesg", {"dmesg", "-W"}, {}, obs_folder);
}
}
