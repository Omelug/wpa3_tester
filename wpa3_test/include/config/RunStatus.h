#pragma once
#include <string>
#include <bits/basic_string.h>

using namespace std;
class RunStatus {
public:
    RunStatus() = default;
    RunStatus(int argc, char ** argv);
    void config_validation();
    void config_requirement();
private:
    static string findConfigByTestName(const string &name);
};
