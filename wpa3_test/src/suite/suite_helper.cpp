#include "suite/suite_helper.h"

#include <memory>

#include "default.h"
#include "config/RunStatus.h"

namespace wpa3_tester::suite::helper{
using namespace std;
using namespace filesystem;

//TODO skip non existing configs?
unique_ptr<RunStatus> load_test_rs(const path &test_folder){
	const auto config_path = test_folder / TEST_CONFIG_NAME;
	if(!exists(config_path)) throw runtime_error("test config file does not exist");
	auto rs = make_unique<RunStatus>();
	rs->config_path(absolute(config_path));
	rs->config(RunStatus::config_validation(rs->config_path()));
	rs->config_path(config_path);
	rs->run_folder(test_folder);
	rs->load_actor_interface_mapping();
	return rs;
}

vector<path> get_suite_test_folders(const path &suite_dir){
	vector<path> folders;
	if(!exists(suite_dir) || !is_directory(suite_dir)) return folders;
	error_code ec;
	for(const auto &entry: directory_iterator(suite_dir, ec)){
		if(!entry.is_directory()) continue;
		if(entry.path().filename() == TEST_SUITE_CONFIG_DIR) continue;
		folders.push_back(entry.path());
	}
	return folders;
}
}
