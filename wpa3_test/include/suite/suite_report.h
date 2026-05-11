#pragma once
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "config/RunSuiteStatus.h"
#include "DoS_hard/suite_dos_attacks.h"

namespace wpa3_tester::suite{
inline std::map<std::string,std::function<void(RunSuiteStatus &)>> suite_report_map = {
	{"access_point_res_list", generate_suite_report},
};

}
