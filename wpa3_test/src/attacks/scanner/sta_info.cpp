#include "attacks/scanner/sta_info.h"

#include <fstream>
#include "attacks/components/setup_connections.h"
#include "config/RunStatus.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/log.h"
#include "scan/active/scan_AP.h"
#include "scan/active/scan_STA.h"
#include "setup/program.h"
#include "system/utils.h"

using namespace std;
using namespace filesystem;

namespace wpa3_tester::sta_info{

void setup_attack(RunStatus &rs){
	components::setup_AP(rs, "scanner");
}

void run_attack(RunStatus &rs){
	rs.start_observers();

	const string ssid = hostapd::get_ssid(rs, "scanner");
	const string password = hostapd::get_password(rs, "scanner");

	log(LogLevel::INFO, "");
	log(LogLevel::INFO, "To test STA, connect to AP '{}' with password '{}'", ssid, password);
	const auto &att_cfg = rs.config().at("attack_config");
	const auto scanner = rs.get_actor("scanner");

	scan::ScanAP scan_ap{};
	scan_ap.bssid = scanner.get(SK::mac);
	const int timeout = att_cfg.at("scan_timeout_sec").get<int>();
	const path stations_pcap = rs.run_folder() / "stations.pcap";

	scan::station_scan(scan_ap, scanner.get(SK::sniff_iface), timeout, stations_pcap);
	set_public_perms(stations_pcap);

	{
		const path stations_txt = rs.run_folder() / "station_scan.txt";
		ofstream ofs(stations_txt);
		ofs << "Stations for AP " << scanner.get(SK::mac) << "\n";
		ofs << "Found: " << scan_ap.stations.size() << "\n";
		for(const auto &sta : scan_ap.stations)
			ofs << "  [STA] " << sta.mac << "\n";
		ofs.close();
		set_public_perms(stations_txt);
	}

	nlohmann::json sta_list = nlohmann::json::array();
	for(const auto &sta : scan_ap.stations)
		sta_list.push_back(sta.mac);

	rs.save_result({
		{"ap_mac",        scanner["mac"]},
		{"station_count", static_cast<int>(scan_ap.stations.size())},
		{"stations",      sta_list},
	});
}

}
