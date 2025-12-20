#include <iostream>
#include "include/config/RunStatus.h"
using namespace std;


static RunStatus r;
int main(const int argc, char *argv[])  {
    r = RunStatus(argc,argv);
    r.config_validation();
    r.config_requirement();
    return 0;
}
