#include <iostream>
#include "config/RunStatus.h"
#include <csignal>
#include <thread>

#include "logger/log.h"
#include "system/ProcessManager.h"

using namespace wpa3_tester;
using namespace std;
static RunStatus* globalRunStatus = nullptr;

void signal_handler(const int signum) {
    if (globalRunStatus) {globalRunStatus->process_manager.stop_all();}
    exit(signum);
}

int main(const int argc, char *argv[])  {
   	RunStatus runStatus(argc, argv);
    globalRunStatus = &runStatus;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    runStatus.config_validation();

    namespace fs = filesystem;
    const fs::path base = fs::current_path();
    const fs::path data_root = base / "data" / "wpa3_test" / "run" / runStatus.config["name"];
    const fs::path last_run = data_root / "last_run";

    // Ensure parent directories exist
    error_code ec;
    fs::create_directories(data_root, ec);
    if (ec) {
        cerr << "CRITICAL ERROR: " << last_run.string() << " Error: " << ec.message() << endl;
        log(LogLevel::ERROR, "Failed to create run base directory: %s: %s", data_root.string().c_str(), ec.message().c_str());
        throw runtime_error("Unable to create run base directory");
    }
    runStatus.run_folder = last_run.string(); //TODO should be changable with argument

    if(runStatus.only_stats){
        runStatus.stats_test();
        return 0;
    }

    runStatus.config_requirement(); //include req validation
    runStatus.setup_test();

    //debug_step();

    runStatus.run_test();
    runStatus.stats_test();

    return 0;
}
