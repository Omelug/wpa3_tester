#include <iostream>
#include "include/config/RunStatus.h"
using namespace std;


static RunStatus runStatus;
int main(const int argc, char *argv[])  {
    runStatus = RunStatus(argc,argv);
    runStatus.config_validation();
    runStatus.config_requirement(); //include validation
    runStatus.setup_test();

    return 0;
}
