#pragma once
#include "config/RunStatus.h"
#include "config/Actor_Config/Actor_Config_external.h"

namespace wpa3_tester::external_info{
struct ApEntry{
	Actor_Config_external cfg;
	std::set<Tins::HWAddress<6>> stations;
};

using ApInfoMap = std::map<Tins::HWAddress < 6>
,
ApEntry
>;
using StaInfoMap = std::map<Tins::HWAddress < 6>
,
Actor_Config_external
>;

void run_attack(RunStatus & rs);
}
