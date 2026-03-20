#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::program{
    // for start and throw error s if called with invalid  actor
    void start(RunStatus &rs, const std::string &actor_name);
}
