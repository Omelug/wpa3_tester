#include <iostream>
#include "config/RunStatus.h"
#include <csignal>
#include <unistd.h>
#include <argparse/argparse.hpp>
#include <yaml-cpp/yaml.h>
#include "config/RunSuiteStatus.h"
#include "logger/error_log.h"
#include "setup/config_parser.h"
#include "system/ProcessManager.h"

using namespace wpa3_tester;
using namespace std;
using namespace filesystem;


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
           .help("List all named tests")
            .implicit_value(true)
            .default_value(false);

    // test suites
    program.add_argument("--test_suite")
          .help("Find name by test suite")
          .metavar("NAME");

    program.add_argument("--test_suite_list")
           .help("List all named test suites")
            .implicit_value(true)
            .default_value(false);

    // direct config
    program.add_argument("--config")
            .help("Path to config file of test run")
            .metavar("PATH");

    // only stats flag
    program.add_argument("--only_stats")
           .help("Generate statistics only without running tests")
            .implicit_value(true)
            .default_value(false);

    try{
        program.parse_args(argc, argv);
    } catch(const runtime_error &err){
        throw config_error(err.what());
    }


    //checks //TODO rozšířit
    if(program.get<bool>("--test_list") && program.get<bool>("--test_suite_list"))
        throw config_error("Cant use both lists");
    if(2 <= (program.present<string>("--test").has_value() +
            program.present<string>("--test_suite").has_value() +
            program.present<string>("--config").has_value()))
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

    if(const auto config_path = program.present<string>("--config")){
        const bool only_stats = program.get<bool>("--only_stats");
        YAML::Node config = YAML::LoadFile(config_path.value());
        nlohmann::json config_json = yaml_to_json(config);
        if(config_json.contains("config_type") && config_json.at("config_type") == "test_suite"){
            RunSuiteStatus rss(config_path.value());
            rss.only_stats = only_stats;
            rss.execute();
        }else{
            RunStatus rs(config_path.value());
            rs.only_stats = only_stats;
            rs.execute();
        }
    }

    if(const auto testName = program.present<string>("--test")){
        const bool only_stats = program.get<bool>("--only_stats");
        string test_config = RunStatus::findConfigByTestName(testName.value());
        RunStatus rs(test_config, testName.value());
        rs.only_stats = only_stats;
        rs.execute();
    }

    if(const auto testSuiteName = program.present<string>("--test_suite")){
        const bool only_stats = program.get<bool>("--only_stats");
        string test_config = RunSuiteStatus::findConfigByTestSuiteName(testSuiteName.value());
        RunSuiteStatus rss(test_config, testSuiteName.value());
        rss.only_stats = only_stats;
        rss.execute();
    }
}

int main(const int argc, char *argv[])  {

    if (geteuid() != 0) {
        cerr << "Error: must be run as root (sudo)" << endl;
        return 1;
    }

    argparse::ArgumentParser program("WPA3_tester", "1.0");
    parse_arguments(program, argc, argv);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    solve_arguments(program);
    return 0;
}
