#pragma once
#pragma once
#include "observer/tshark_wrapper.h"

namespace wpa3_tester::reflection{
    void setup_attack(RunStatus& rs);
    void run_attack(RunStatus& rs);
    //void stats(const RunStatus& rs);
}
