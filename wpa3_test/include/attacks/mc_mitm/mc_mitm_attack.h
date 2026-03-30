#pragma once
#include "attacks/mc_mitm/mc_mitm.h"
#include "config/RunStatus.h"

using namespace std;
using namespace filesystem;

// This module is rewrite of python mc-mitm
// integrated for better test speed
// https://github.com/vanhoefm/mc-mitm?tab=readme-ov-fil
namespace wpa3_tester::mc_mitm{
    void setup_attack(RunStatus& rs);
    void run_attack(RunStatus& rs);
}
