#include "attacks/DoS_soft/bl0ck/bl0ck.h"
#include "config/RunStatus.h"
#include <chrono>
#include <thread>

#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "observer/tshark_wrapper.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::test_sae_commit_monitor{
    using namespace std;
    using namespace filesystem;
    using namespace Tins;
    using namespace chrono;

    void speed_observation_start(RunStatus &rs);
    void run_attack(RunStatus& rs);
    void stats_attack(const RunStatus& rs);
}
