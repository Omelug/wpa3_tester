#pragma once
#include <string>
using namespace  std;
class RunStatus {
public:
    RunStatus() = default;
    RunStatus(int argc, char ** argv);
    void config_validation();
    void config_requirement();
private:
    static string findConfigByTestName(const string &name);
    string finalPath;
};
