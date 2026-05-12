#include "system/utils.h"
#include <chrono>
#include <filesystem>
#include <iomanip>
#include <sstream>
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

void print_exception_tree(const exception &e, ostream &os, int level){
	os << string(level * 2, ' ') << "- " << e.what() << endl;
	try{
		rethrow_if_nested(e);
	} catch(const exception &nested){
		print_exception_tree(nested, os, level + 1);
	} catch(...){}
}

string join(const vector<string> &v, const string &sep){
	string out;
	for(size_t i = 0; i < v.size(); ++i){
		if(i) out += sep;
		out += v[i];
	}
	return out;
}
}
