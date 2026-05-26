#include "system/utils.h"
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>
#include <sys/utsname.h>
#include <vector>
#include "logger/error_log.h"

namespace wpa3_tester{
using namespace std;
using namespace filesystem;

string current_time_string(){
	const auto now = chrono::system_clock::now();
	const auto timer = chrono::system_clock::to_time_t(now);
	tm bt{};
	localtime_r(&timer, &bt);

	ostringstream oss;
	oss << put_time(&bt, "%Y-%m-%d %H:%M:%S");
	return oss.str();
}

string git_commit_hash(){
	FILE *pipe = popen("git rev-parse --short HEAD 2>/dev/null", "r");
	if(!pipe){ return "unknown"; }
	char buf[16]{};
	if(fgets(buf, sizeof(buf), pipe) == nullptr){ pclose(pipe); return "unknown"; }
	pclose(pipe);
	string result(buf);
	if(!result.empty() && result.back() == '\n'){ result.pop_back(); }
	return result.empty() ? "unknown" : result;
}

string kernel_version(){
	utsname uts{};
	if(uname(&uts) != 0){ return "unknown"; }
	return string(uts.sysname) + " " + uts.release + " " + uts.machine;
}


string relative_from(const string &base_dir_name, const string &config_path){
	const path config_full_path = absolute(config_path);
	const path config_dir = config_full_path.parent_path();

	path current = config_dir;
	string relative_path;

	while(current != current.parent_path()){
		if(current.filename() == base_dir_name){
			return relative_path.empty() ? "." : relative_path;
		}
		if(!relative_path.empty()){
			relative_path = current.filename().string().append("/").append(relative_path);
		} else{
			relative_path = current.filename().string();
		}
		current = current.parent_path();
	}

	if(!current.empty() && current.filename() == base_dir_name){
		return relative_path.empty() ? "." : relative_path;
	}
	throw config_err("folder name not found");
}

string join(const vector<string> &v, const string &sep){
	string out;
	for(size_t i = 0; i < v.size(); ++i){
		if(i) out += sep;
		out += v[i];
	}
	return out;
}

static constexpr auto PUBLIC_FILE_PERMS =
    perms::owner_read | perms::owner_write |
    perms::group_read | perms::group_write |
    perms::others_read | perms::others_write;  // 0666

void resolve_relative_paths(nlohmann::json &node, const path &base_dir){
	if(node.is_string()){
		const string &s = node.get<string>();
		if(s.size() >= 2 && s[0] == '.' && (s[1] == '/' || s[1] == '.')){
			node = weakly_canonical(base_dir / path(s)).string();
		}
	} else if(node.is_object()){
		for(auto &[key, val] : node.items()){
			resolve_relative_paths(val, base_dir);
		}
	} else if(node.is_array()){
		for(auto &elem : node){
			resolve_relative_paths(elem, base_dir);
		}
	}
}

void create_public_dirs(const path &p){
	// Track which directories don't exist yet
	vector<path> to_chmod;
	path current = p;
	while(!current.empty()){
		if(!exists(current)){
			to_chmod.push_back(current);
		} else {
			break;  // stop at first existing directory
		}
		path parent = current.parent_path();
		if(parent == current) break;  // reached root
		current = parent;
	}

	create_directories(p);

	// Set permissions only on newly created directories
	for(const auto &dir : to_chmod){
		permissions(dir, perms::all);
	}
}

void create_public_dirs(const path &p, error_code &ec){
	vector<path> to_chmod;
	path current = p;
	while(!current.empty()){
		if(!exists(current)){
			to_chmod.push_back(current);
		} else {
			break;
		}
		path parent = current.parent_path();
		if(parent == current) break;
		current = parent;
	}

	create_directories(p, ec);
	if(ec) return;

	for(const auto &dir : to_chmod){
		permissions(dir, perms::all, ec);
		if(ec) return;
	}
}

void set_public_perms(const path &p){
	error_code ec;
	const auto mode = is_directory(p, ec) ? perms::all : PUBLIC_FILE_PERMS;
	permissions(p, mode, ec);
}
}
