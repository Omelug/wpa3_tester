#include "../../include/config/RunStatus.h"
#include "../../include/logger/error_log.h"

#include <string>
using namespace std;

string RunStatus::findConfigByTestName(const string& name) {
    //TODO
    throw config_error("Neznámý test: %s", name.c_str());
    return ""; //TODO
}

RunStatus::RunStatus(int argc, char **argv) {

}
