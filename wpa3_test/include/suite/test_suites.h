#pragma once
#include <functional>
#include <map>
#include <string>

#include "suite_report.h"
#include "attacks/Enterprise/eap_helper.h"
#include "config/RunSuiteStatus.h"
#include "DoS_soft/bl0ck/bl0ck_test_suites.h"
#include "DoS_soft/malformed_eapol1/malformed_eapol1_suite.h"
#include "Enterprise/enterprise_filler_helper.h"
#include "downgrade/owe_trans_filler.h"
#include "downgrade/wpa3_trans_downgrade_filler.h"
#include "Enterprise/invalid_curve/invalid_curve_filler.h"
#include "Enterprise/reflection_attack/reflection_attack_filler.h"

namespace wpa3_tester::suite{

/* map of test_suite_name->post-run callback function */
inline std::map<std::string,std::function<void(RunSuiteStatus &)>> test_suite_setup_map = {
	{"reflection_attack_filler",    enterprise_filler_helper::setup_suite},
	{"invalid_curve_filler",        enterprise_filler_helper::setup_suite},
	{"wpa3_trans_downgrade_filler", wpa3_trans_downgrade_filler::setup_suite},
};

/* map of test_suite_name->post-run callback function */
inline std::map<std::string,std::function<void(RunSuiteStatus &)>> test_suite_report_map = {
	{"access_point_res_list", generate_suite_report},
	{"bl0ck_mac_gen", bl0ck_test_suites::generate_bl0ck_mac_gen_report},
	{"malformed_eapol1_filler", malformed_eapol1_filler::generate_report},
	{"reflection_attack_filler", reflection_attack_filler::generate_report},
	{"invalid_curve_filler",          invalid_curve_filler::generate_report},
	{"owe_trans_filler",              owe_trans_filler::generate_report},
	{"wpa3_trans_downgrade_filler",   wpa3_trans_downgrade_filler::generate_report},
};

}
