#pragma once
#include <functional>
#include <map>
#include <string>

#include "DoS_soft/bl0ck/bl0ck_test_suites.h"
#include "DoS_soft/channel_switch/channel_switch_rogueAP.h"
#include "DoS_soft/channel_switch/channel_switch_versions.h"
#include "DoS_soft/deauth/deauth_suite.h"
#include "DoS_soft/expected_vht_beacon/expected_vht_beacon_suite.h"
#include "DoS_soft/malformed_eapol1/malformed_eapol1_suite.h"
#include "attacks/enterprise/eap_helper.h"
#include "config/RunSuiteStatus.h"
#include "downgrade/owe_trans_filler.h"
#include "downgrade/wpa3_downgrade_filler.h"
#include "enterprise/enterprise_filler_helper.h"
#include "enterprise/invalid_curve/invalid_curve_filler.h"
#include "enterprise/reflection_attack/reflection_attack_filler.h"
#include "mc_mitm/ssid_confusion_filler.h"
#include "scan/ap_info_wpa3_filler.h"
#include "scan/iface_info_filler.h"
#include "two_iface/active_test_filler.h"
#include "two_iface/injection_test_filler.h"

namespace wpa3_tester::visual {
/* map of test_suite_name->post-run callback function */
inline std::map<std::string, std::function<void(RunSuiteStatus &)>> test_suite_setup_map = {
	{ "wpa3_downgrade_filler", wpa3_downgrade_filler::setup_suite },
	{ "reflection_attack_filler", enterprise_filler_helper::setup_suite },
	{ "invalid_curve_filler", enterprise_filler_helper::setup_suite },
	{ "ssid_confusion_filler", ssid_confusion_filler::setup_suite },
	//{"CSA_rogueAP_internal_filler", channel_switch_rogueAP::setup_suite},
};

/* map of test_suite_name->post-run callback function */
inline std::map<std::string, std::function<void(RunSuiteStatus &)>> test_suite_report_map = {
	{ "bl0ck_filler", bl0ck_test_suites::Bl0ckTestEntry::generate_report },
	{ "channel_switch_versions", channel_switch_filler::CsaVersionTestEntry::generate_report },
	{ "deauth_filler", deauth_suite::DeauthTestEntry::generate_report },
	{ "malformed_eapol1_filler", malformed_eapol1_filler::MalformedEapol1TestEntry::generate_report },
	{ "reflection_attack_filler", reflection_attack_filler::generate_report },
	{ "invalid_curve_filler", invalid_curve_filler::generate_report },
	{ "owe_trans_filler", owe_trans_filler::generate_report },
	{ "wpa3_downgrade_filler", wpa3_downgrade_filler::generate_report },
	{ "active_test_filler", active_test_filler::generate_report },
	{ "injection_test_filler", injection_test_filler::generate_report },
	{ "iface_info_filler", iface_info_filler::generate_report },
	{ "ap_info_wpa3_filler", ap_info_wpa3_filler::generate_report },
	{ "CSA_rogueAP_internal_filler", channel_switch_rogueAP::CsaTestEntry::generate_report },
	{ "CSA_ex_filler", channel_switch_rogueAP::CsaTestEntry::generate_report },
	{ "expected_vht_beacon_2_4GHz_filler", expected_vht_beacon_suite::ExpVhtTestEntry::generate_report },
	{ "expected_vht_beacon_5GHz_filler", expected_vht_beacon_suite::ExpVhtTestEntry::generate_report },
	{ "expected_vht_beacon_rogueAP_filler", expected_vht_beacon_suite::ExpVhtTestEntry::generate_report },
	{ "expected_vht_beacon_ex_filler", expected_vht_beacon_suite::ExpVhtTestEntry::generate_report },
	{ "expected_vht_beacon_ex_client_filler", expected_vht_beacon_suite::ExpVhtTestEntry::generate_report },
	{ "expected_vht_beacon_ex_client_5GHz_filler", expected_vht_beacon_suite::ExpVhtTestEntry::generate_report },
	//{"malformed_eapol1_basic_suite", malformed_eapol1_basic_visual::generate_report},
};

}
