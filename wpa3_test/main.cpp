#include <iostream>
#include "config/RunStatus.h"
#include "attacks/attacks.h"
#include <csignal>
#include <thread>

#include "ProcessManager.h"

using namespace std;

static RunStatus* globalRunStatus = nullptr;

void signal_handler(int signum) {
    if (globalRunStatus) {
        globalRunStatus->process_manager.stop_all();
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
    std::this_thread::sleep_for(std::chrono::seconds(3));
    runStatus.setup_test();
    attack_run[runStatus.config["attacker_module"]](runStatus);
    return 0;
}
