#include <iostream>
#include <unistd.h>
#include <argparse/argparse.hpp>
#include <yaml-cpp/yaml.h>
#include "config/RunStatus.h"

#include "inteprrupt.h"
#include "config/RunSuiteStatus.h"
#include "logger/error_log.h"
#include "setup/config_parser.h"
#include "system/ProcessManager.h"

using namespace wpa3_tester;
using namespace std;
using namespace filesystem;

void parse_arguments(argparse::ArgumentParser &program, const int argc, char *argv[]){
	// test
	program.add_argument("--test").help("Find name by test").metavar("NAME");

	program.add_argument("--test_list").help("List all named tests").implicit_value(true).default_value(false);

	// test suites
	program.add_argument("--test_suite").help("Find name by test suite").metavar("NAME");

	program.add_argument("--test_suite_list").help("List all named test suites").implicit_value(true).
			default_value(false);

	// direct config
	program.add_argument("--config").help("Path to config file of test run").metavar("PATH");

	try{
		program.parse_args(argc, argv);
	} catch(const run_err &err){
		throw config_err(err.what());
	}

	if(program.get<bool>("--test_list") && program.get<bool>("--test_suite_list"))
		throw config_err("Cant use both lists");
	const bool has_config = program.present<string>("--config").has_value();
	const bool has_test = program.present<string>("--test").has_value();
	const bool has_suite = program.present<string>("--test_suite").has_value();
	if(has_config && (has_test || has_suite)) throw config_err("Can't combine --config with --test/--test_suite");
}

static void solve_arguments(const argparse::ArgumentParser &program){
	//-----------  prints
	if(program.get<bool>("--test_list")){
		if(const auto testName = program.present<string>("--test")){
			const auto tests = RunStatus::scan_attack_configs(TEST);
			if(tests.empty()){
				cout << "In program are not any tests" << endl;
				return;
			}
			cout << "Test: " << testName.value() << " -> " << tests.at(testName.value()) << endl;
		} else if(const auto testSuiteName = program.present<string>("--test_suite")){
			RunSuiteStatus::print_tests_in_suite(testSuiteName.value());
		} else{
			RunStatus::print_test_list();
		}
	}
	if(program.get<bool>("--test_suite_list")){
		if(const auto testSuiteName = program.present<string>("--test_suite")){
			const auto tests = RunStatus::scan_attack_configs(TEST_SUITE);
			if(tests.empty()){
				cout << "In program are not any tests" << endl;
				return;
			}
			cout << "Test-suite: " << testSuiteName.value() << " -> " << tests.at(testSuiteName.value()) << endl;
		} else{
			RunSuiteStatus::print_test_suite_list();
		}
	}

	if(const auto config_path = program.present<string>("--config")){
		//const bool only_stats = program.get<bool>("--only_stats");
		YAML::Node config = YAML::LoadFile(config_path.value());
		if(nlohmann::json config_json = yaml_to_json(config); config_json.contains("config_type") && config_json.at("config_type") == "test_suite"){
			RunSuiteStatus rss(config_path.value());
			rss.execute();
		} else{
			RunStatus rs(config_path.value());
			rs.execute();
		}
	}

	if(const auto testName = program.present<string>("--test")){
		if(!program.present<string>("--test_suite")){
			string test_config = RunStatus::findConfigByTestName(testName.value());
			RunStatus rs(test_config, testName.value());
			rs.execute();
		}
	}

	if(const auto testSuiteName = program.present<string>("--test_suite")){
		string test_config = RunSuiteStatus::findConfigByTestSuiteName(testSuiteName.value());
		RunSuiteStatus rss(test_config, testSuiteName.value());
		//rss.only_stats = program.get<bool>("--only_stats");
		if(const auto testName = program.present<string>("--test")){
			rss.execute(testName.value());
		} else{
			rss.execute();
		}
	}
}

int main(const int argc, char *argv[]){
	setup_signals();
	if(geteuid() != 0){
		cerr << "Error: must be run as root (sudo)" << endl;
		return 1;
	}

	argparse::ArgumentParser program("WPA3_tester", "1.0");
	parse_arguments(program, argc, argv);
	solve_arguments(program);
	return 0;
}