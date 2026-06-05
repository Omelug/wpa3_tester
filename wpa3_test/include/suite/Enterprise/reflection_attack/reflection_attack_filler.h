#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

#include "config/RunStatus.h"
#include "config/RunSuiteStatus.h"
#include "logger/log.h"
#include "suite/DoS_soft/bl0ck/bl0ck_test_suites.h"
#include "system/utils.h"

namespace wpa3_tester::suite::reflection_attack_filler{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

void setup_suite(const RunSuiteStatus &rss);
void generate_report(RunSuiteStatus &rss);

}