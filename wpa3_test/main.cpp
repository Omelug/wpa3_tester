#include <iostream>
#include "include/config/RunStatus.h"
#include "attacks/attacks.h"

using namespace std;

static RunStatus runStatus;
int main(const int argc, char *argv[])  {
    runStatus = RunStatus(argc,argv);
    runStatus.config_validation();
    runStatus.config_requirement(); //include validation
	runStatus.setup_test();
    attack_run[runStatus.config["attacker_module"]](runStatus);
    return 0;
}
