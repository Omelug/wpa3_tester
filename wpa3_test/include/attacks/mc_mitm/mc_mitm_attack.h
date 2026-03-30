#pragma once
#include "attacks/mc_mitm/mc_mitm.h"
#include "config/RunStatus.h"

using namespace std;
using namespace filesystem;

namespace wpa3_tester::mc_mitm{
    void setup_attack(RunStatus& rs);
    void run_attack(RunStatus& rs);
}
