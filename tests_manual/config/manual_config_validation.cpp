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

    for(const auto &entry : recursive_directory_iterator(ATTACK_CONFIG())){
        if(!entry.is_regular_file() || entry.path().extension() != ".yaml") continue;
        if(RunStatus::should_skip(entry.path())) continue;

        const string rel = relative(entry.path(), ATTACK_CONFIG()).string();
        try{
            if(is_suite(entry.path())){
	            const auto suite_json = RunSuiteStatus::config_validation(entry.path());
	            for(const auto &[src_name, src_info] : suite_json.at("tests").items()){
	                if(src_info.value("type", "") == "actor_filler"){
	                    cout << "[SKIP] " << rel << "/" << src_name << " (actor_filler)\n";
	                    continue;
	                }
	                if(src_info.contains("path")){
	                    RunStatus::config_validation(absolute(entry.path().parent_path() / src_info.at("path").get<string>()));
	                } else if(src_info.contains("test_name")){
	                    RunStatus::config_validation(RunStatus::findConfigByTestName(src_info.at("test_name").get<string>()));
	                }
	            }
            }else{
	            RunStatus::config_validation(entry.path());
            }
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
