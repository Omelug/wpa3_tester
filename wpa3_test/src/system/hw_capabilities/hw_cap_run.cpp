#include <cstdlib>
#include <random>
#include <string>
#include <vector>
#include <reproc++/drain.hpp>
#include <reproc++/reproc.hpp>
#include <sys/types.h>
#include <sys/wait.h>

#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"

namespace wpa3_tester{
using namespace std;
using namespace filesystem;

void hw_capabilities::run_in(const string &cmd, const path &cwd = current_path()){
	const string full_cmd = "cd " + cwd.string() + " && " + cmd;
	if(system(full_cmd.c_str()) != 0){
		throw run_err("Command failed: " + cmd);
	}
}

vector<string> wrap_with_netns(const vector<string> &argv, const optional<string> &netns){
	if(!netns.has_value()){
		return argv;
	}

	vector<string> full_argv;
	// Pre-allocate space: 4 for "ip netns exec [name]" + the original command size
	full_argv.reserve(argv.size() + 4);

	full_argv.insert(full_argv.end(), {"ip", "netns", "exec", *netns});
	full_argv.insert(full_argv.end(), argv.begin(), argv.end());

	return full_argv;
}

int hw_capabilities::run_cmd(const vector<string> &argv, const optional<string> &netns, const bool print){
	if(argv.empty()) return -1;

	const auto full_argv = wrap_with_netns(argv, netns);

	vector<char *> args;
	args.reserve(full_argv.size() + 1);
	for(auto &s: full_argv){ args.push_back(const_cast<char *>(s.c_str())); }
	args.push_back(nullptr);

	reproc::process proc;
	reproc::options options;
	if(print){
		options.redirect.parent = true;
		options.redirect.out.type = reproc::redirect::parent;
		options.redirect.err.type = reproc::redirect::parent;
	}
	if(const error_code ec = proc.start(full_argv, options)){
		if(print) log(LogLevel::ERROR, "Failed to start {} {}", full_argv[0], ec.message());
		return -1;
	}

	auto [status, wait_ec] = proc.wait(reproc::infinite);
	if(wait_ec){
		if(print) log(LogLevel::ERROR, "Wait failed: {}", wait_ec.message());
		return -1;
	}
	if(status != 0){
		if(print){
			log(LogLevel::ERROR, "Command failed! Status: {} | Full command: {}", status, join(full_argv, " "));
		}
		return -1;
	}
	return status;
}

string hw_capabilities::run_cmd_output(const vector<string> &argv, const optional<string> &netns){
	if(argv.empty()) return {};

	const auto full_argv = wrap_with_netns(argv, netns);

	reproc::process proc;
	reproc::options options;

	options.redirect.out.type = reproc::redirect::pipe;
	options.redirect.err.type = reproc::redirect::pipe;

	error_code ec = proc.start(full_argv, options);
	if(ec){ return {}; }

	string output_str;
	reproc::sink::string sink_obj(output_str);

	ec = reproc::drain(proc, sink_obj, reproc::sink::null);
	if(ec){ return {}; }

	auto [status, wait_ec] = proc.wait(reproc::infinite);
	if(wait_ec){ return {}; }
	return output_str;
}

// ---------------- git helpers

bool hw_capabilities::git_available(){
	return run_cmd({"git", "--version"}, nullopt, false) == 0;
}

void hw_capabilities::git_clone_or_pull(const string &url, const path &dest){
	if(!git_available()) throw req_err("git is not available");
	if(!exists(dest)){
		// Create parent directories if needed
		const path parent = dest.parent_path();
		if(!parent.empty() && !exists(parent)){
			create_directories(parent);
		}
		log(LogLevel::INFO, "Cloning {} to {}...", url, dest.string());
		run_cmd({"git", "clone", url, dest.string()});
	} else{
		log(LogLevel::INFO, "Updating {}...", dest.string());
		run_cmd({"git", "-C", dest.string(), "pull"});
	}
}

// ---------------- exec -. errors
/*
void hw_capabilities::exec(const vector<string> &cmd, const bool check){
	const string full = join(cmd, " ");
	if(const int ret = system(full.c_str()); check && ret != 0)
		throw run_err("Command failed: " + full);
}*/
}