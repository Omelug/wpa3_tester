#pragma once
#include <iosfwd>

#include "config/RunStatus.h"

// functions here don't check if stream is open, have to be checked before
namespace wpa3_tester::report{
void attack_config_table(std::ofstream &report, const RunStatus &rs);
void attack_mapping_table(std::ofstream &report, const RunStatus &rs);
}