#include "attacks/scanner/sta_info.h"

#include "attacks/components/setup_connections.h"
#include "config/RunStatus.h"
#include "config/Actor_Config/Actor_Config_external.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/log.h"
#include "scan/active/scan_STA.h"

using namespace std;

namespace wpa3_tester::sta_info{
void setup_attack(RunStatus &rs){
	components::setup_AP(rs, "scanner");
}

void run_attack(RunStatus &rs){
	rs.start_observers();

	const string ssid = hostapd::get_ssid(rs, "scanner");
	const string password = hostapd::get_password(rs, "scanner");
	log(LogLevel::INFO, "To test STA, connect to AP '{}' with password '{}'", ssid, password);
	const auto &att_cfg = rs.config().at("attack_config");
	const auto scanner = rs.get_actor("scanner");

	const int timeout = att_cfg.at("scan_timeout_sec").get<int>();

	const Actor_Config_external sta = scan::scan_sta_actor(scanner.get(SK::sniff_iface), scanner.get(SK::mac), timeout);

	rs.save_result({{"ap_mac", scanner.get(SK::mac)}, {"station", sta.to_json()},});
}
}