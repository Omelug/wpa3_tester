#include <iostream>
#include "config/RunStatus.h"
#include <csignal>
#include <thread>
#include "ProcessManager.h"

using namespace std;

static RunStatus* globalRunStatus = nullptr;

void signal_handler(const int signum) {
    if (globalRunStatus) {
        globalRunStatus->process_manager.stop_all();
    }
    exit(signum);
}

int main(const int argc, char *argv[])  {
   	RunStatus runStatus(argc, argv);
    globalRunStatus = &runStatus;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    runStatus.config_validation();
    runStatus.config_requirement(); //include validation
    this_thread::sleep_for(std::chrono::seconds(3)); //TODO for interface to setup
    runStatus.setup_test();
    runStatus.run_test();
    return 0;
}
