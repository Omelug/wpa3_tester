#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include <cassert>
#include "ex_program/hostapd/hostapd.h"

namespace wpa3_tester::dragondrain{
    using namespace std;
    using namespace filesystem;
    using namespace Tins;
    using namespace chrono;

    void run_attack(RunStatus& rs){
        rs.start_observers();
        this_thread::sleep_for(seconds(10));
    }

    void stats_attack(const RunStatus &rs){

    }
}
