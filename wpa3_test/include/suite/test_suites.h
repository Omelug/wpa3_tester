#pragma once
#include <functional>
#include <map>
#include <string>
#include "config/RunSuiteStatus.h"
#include "DoS_soft/bl0ck/bl0ck_test_suites.h"

namespace wpa3_tester::suite{

/* map of test_suite_name->post-run callback function */
inline std::map<std::string,std::function<void(RunSuiteStatus &)>> test_suite_callback_map = {
	{"access_point_res_list", generate_suite_report},
	{"bl0ck_mac_gen", bl0ck_test_suites::generate_bl0ck_mac_gen_report},
};

}
