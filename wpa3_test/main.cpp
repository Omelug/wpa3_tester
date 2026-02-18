#include <iostream>
#include "config/RunStatus.h"
#include <csignal>
#include <thread>
#include <argparse/argparse.hpp>
#include <yaml-cpp/yaml.h>

#include "config/RunSuiteStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "setup/config_parser.h"
#include "system/ProcessManager.h"

using namespace wpa3_tester;
using namespace std;
using namespace filesystem;

static RunStatus* globalRunStatus = nullptr;

void signal_handler(const int signum) {
    if (globalRunStatus) {globalRunStatus->process_manager.stop_all();}
    exit(signum);
}

void parse_arguments(argparse::ArgumentParser & program, const int argc, char *argv[]){
    // test
    program.add_argument("--test")
          .help("Find name by test")
          .metavar("NAME");

    program.add_argument("--test_list")
           .help("List all named lists")
            .implicit_value(true)
            .default_value(false);

    // test suites
    program.add_argument("--test")
          .help("Find name by test")
          .metavar("NAME");

    program.add_argument("--test_list")
           .help("List all named lists")
            .implicit_value(true)
            .default_value(false);

    // direct config
    program.add_argument("--config")
            .help("Path to config file of test run")
            .metavar("PATH");

    // flags
    /*program.add_argument("--only_stats")
            .help("Run only statistics for an already finished test (no setup/attack)")
            .default_value(false)
            .implicit_value(true);*/

    try{
        program.parse_args(argc, argv);
    } catch(const runtime_error &err){
        throw config_error(err.what());
    }

    /*if(runStatus.only_stats){
          runStatus.stats_test();
          return 0;
      }*/

    //checks //TODO rozšířit
    if(program.present("--test_list") && program.present("--test_suite_list"))
        throw config_error("Cant use both lists");
    if(2 <= (program.present("--test").has_value() +
            program.present("--test_suite").has_value() +
            program.present("--config").has_value()))
        throw config_error("Can't combinate  test/test_suite/config");

}

static void solve_arguments(const argparse::ArgumentParser &program){

    // prints
    if(program.get<bool>("--test_list")){
        if(const auto testName = program.present<string>("--test")){
            const auto tests = RunStatus::scan_attack_configs(TEST);
            if (tests.empty()) {cout << "In program are not any tests" << endl; return;}
            cout << "Test: " << testName.value() << " -> " << tests.at(testName.value()) << endl;
        }else if(const auto testSuiteName = program.present<string>("--test_suite")){
            RunSuiteStatus::print_tests_in_suite(testSuiteName.value());
        }else{
            RunStatus::print_test_list();
        }
    }
    if(program.get<bool>("--test_suite_list")){
        if(const auto testSuiteName = program.present<string>("--test_suite")){
            const auto tests = RunStatus::scan_attack_configs(TEST_SUITE);
            if (tests.empty()) {cout << "In program are not any tests" << endl; return;}
            cout << "Test-suite: " << testSuiteName.value() << " -> " << tests.at(testSuiteName.value()) << endl;
        }else{
            RunSuiteStatus::print_test_suite_list();
        }
    }

    if(const auto configPath = program.present<string>("--config")){
        YAML::Node config = YAML::LoadFile(configPath.value());
        nlohmann::json config_json = yaml_to_json(config);
        if(config_json.contains("config_type") && config_json["config_type"] == "test_suite"){
            RunSuiteStatus rss(configPath.value());
            rss.run_folder = RunSuiteStatus::BASE_FOLDER / config_json.at("name") / "last_run";
            rss.execute();
        }else{
            RunStatus rs(configPath.value());
            rs.execute();
        }
    }

    if(const auto testName = program.present<string>("--test")){
        string test_config = RunStatus::findConfigByTestName(testName.value());
        RunStatus rs(test_config);
        rs.run_folder = RunStatus::BASE_FOLDER / testName.value() / "last_run";
        rs.execute();
    }

    if(const auto testSuiteName = program.present<string>("--test_suite")){
        string test_config = RunStatus::findConfigByTestName(testSuiteName.value());
        RunSuiteStatus rss(test_config);
        rss.run_folder = RunSuiteStatus::BASE_FOLDER / testSuiteName.value() / "last_run";
        rss.execute();
    }
}

int main(const int argc, char *argv[])  {

    argparse::ArgumentParser program("WPA3_tester", "1.0");
    parse_arguments(program, argc, argv);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    solve_arguments(program);
    //RunStatus runStatus(program);
    return 0;
}
