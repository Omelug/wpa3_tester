#include "visual/suite_helper.h"

#include <memory>

#include "default.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"

namespace wpa3_tester::visual::helper{
using namespace std;
using namespace filesystem;

unique_ptr<RunStatus> load_test_rs(const path &test_folder){
	const auto config_path = test_folder / TEST_CONFIG_NAME;
	if(!exists(config_path)) throw run_err("test config {} file does not exist", config_path);
	auto rs = make_unique<RunStatus>();
	rs->config_path(absolute(config_path));
	rs->config(RunStatus::config_validation(rs->config_path()));
	rs->config_path(config_path);
	rs->run_folder(test_folder);
	rs->load_actor_interface_mapping();
	return rs;
}
}
