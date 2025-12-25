#include <iostream>
#include "config/RunStatus.h"
#include "attacks/attacks.h"
#include <csignal>
#include "ProcessManager.h"

using namespace std;

static RunStatus* globalRunStatus = nullptr;

void signal_handler(int signum) {
    if (globalRunStatus) {
        globalRunStatus->pm.stop_all();
    }
    std::exit(signum);
}

int main(const int argc, char *argv[])  {
   	RunStatus runStatus(argc, argv);
    globalRunStatus = &runStatus;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    runStatus.config_validation();
    runStatus.config_requirement(); //include validation
    runStatus.setup_test();
    attack_run[runStatus.config["attacker_module"]](runStatus);
    return 0;
}
