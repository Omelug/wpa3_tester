#pragma once
#include <filesystem>
#include <nlohmann/json.hpp>
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite::reflection_attack_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

void setup_suite(const RunSuiteStatus &rss);
void generate_report(RunSuiteStatus &rss);

}