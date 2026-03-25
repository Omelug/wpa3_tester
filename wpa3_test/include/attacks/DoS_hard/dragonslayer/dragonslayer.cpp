#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "logger/error_log.h"
#include <cassert>
#include "ex_program/hostapd/hostapd.h"
#include "logger/log.h"
#include <thread>
#include <chrono>
#include "system/hw_capabilities.h"
#include <filesystem>

#include "attacks/components/setup_connections.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "logger/report.h"
#include "observer/mausezahn_wrapper.h"
#include "observer/observers.h"
#include "observer/tcpdump_wrapper.h"
#include "observer/tshark_wrapper.h"
#include "setup/program.h"

namespace wpa3_tester::CSA_attack{
    using namespace std;
    using namespace filesystem;
    using namespace Tins;
    using namespace chrono;

    // ----------------- MODULE functions ------------------
    void setup_attack(RunStatus& rs){

    }

    void run_attack(RunStatus& rs){

        rs.start_observers();
    }

    void stats_attack(const RunStatus &rs){

    }
}
