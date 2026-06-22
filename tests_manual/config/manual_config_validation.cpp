#include <filesystem>
#include <iostream>
#include <yaml-cpp/yaml.h>
#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "logger/error_log.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester;

static bool is_suite(const path &p){
    try{
        const auto node = YAML::LoadFile(p.string());
        return node["config_type"] && node["config_type"].as<string>() == "test_suite";
    } catch(...){ return false; }
}

int main(){
    int passed = 0, failed = 0;

    for(const auto &entry : recursive_directory_iterator(ATTACK_CONFIG)){
        if(!entry.is_regular_file() || entry.path().extension() != ".yaml") continue;
        if(RunStatus::should_skip(entry.path())) continue;

        const string rel = relative(entry.path(), ATTACK_CONFIG).string();
        try{
            if(is_suite(entry.path()))
                RunSuiteStatus::config_validation(entry.path());
            else
                RunStatus::config_validation(entry.path());
            cout << "[OK]   " << rel << "\n";
            passed++;
        } catch(const exception &e){
            cout << "[FAIL] " << rel << "\n       " << e.what() << "\n";
            failed++;
        }
    }

    cout << "\n--- " << passed << " passed, " << failed << " failed ---\n";
    return failed > 0 ? 1 : 0;
}
