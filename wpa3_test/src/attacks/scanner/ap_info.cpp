#include <future>
#include <sstream>
#include <sys/poll.h>
#include "config/RunStatus.h"

#include "attacks/components/sniffer_helper.h"
#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "attacks/DoS_hard/PMK_gobbler/pmk_gobbler.h"
#include "scan/active/scan_AP.h"
#include "scan/active/scan_EAP.h"
#include "scan/active/scan_STA.h"
#include "system/utils.h"

using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::ap_info{

void run_attack(RunStatus &rs){
	rs.start_observers();
	const auto &att_cfg = rs.config().at("attack_config");
	const auto target_ap = rs.get_actor("target");
	const auto scanner = rs.get_actor("scanner");

	log(LogLevel::DEBUG, "Scanning start");
	scan::ScanAP scan_ap{};
	scan_ap.bssid = target_ap["mac"];
	if(att_cfg.value("beacon_scan", false)){
		const auto timeout = att_cfg.value("beacon_timeout_sec", 10);
		log(LogLevel::DEBUG, "Scanning beacon for {} seconds", timeout);
		auto beacon_pcap = rs.run_folder()/ (target_ap["actor_name"] + ".pcap");
		set_public_perms(beacon_pcap);
		RSN_scan(scanner["iface"], timeout, scan_ap, beacon_pcap);
		{
			const path beacon_txt = rs.run_folder()/ "beacon_scan.txt";
			ofstream ofs(beacon_txt);
			ofs << "Scan results for " << target_ap["mac"] << "\n";
			ofs << scan_ap.to_str() << endl;
			ofs.close();
			set_public_perms(beacon_txt);
		}
	}

	if(att_cfg.value("stations_scan", false)){
		const auto timeout = att_cfg.value("stations_timeout_sec", 10);
		scan::station_scan(scan_ap, scanner["iface"], timeout, path(rs.run_folder()));
	}

	if(att_cfg.value("EAP_scan", false)){
		bool is_eap = false;
		if(scan_ap.rsn){
			for(const auto &suite: scan_ap.rsn.value().akm_cyphers()){
				// Tins::RSNInformation::AKMSuites
				if(suite == RSNInformation::EAP || suite == RSNInformation::EAP_FT || suite ==
					RSNInformation::EAP_SHA256 || suite == RSNInformation::EAP_SHA256_FIPSB || suite ==
					RSNInformation::EAP_SHA384){
					is_eap = true;
					break;
				}
			}
		}
		if(is_eap){
			const auto timeout = att_cfg.value("EAP_timeout_sec", 10);
			log(LogLevel::DEBUG, "AP supports EAP. Scanning identities for {} seconds", timeout);
			scan::active_eap_identity_scan(scanner["iface"], target_ap["mac"], timeout);
		} else{
			log(LogLevel::INFO, "Skipping EAP scan: Beacon RSN does not indicate 802.1X/EAP support.");
		}
	}

	bool acm_triggered = false;
	if(att_cfg.value("ACM_trigger", false)){
		const optional<sae_helper::SAEPair> sae_params = cookie_guzzler::get_commit_values(
			rs, scanner["iface"], scanner["sniff_iface"], scan_ap.ssid, target_ap["mac"], 30);
		const auto [cookie, count] = pmk_gobbler::trigger_acm(scanner["sniff_iface"], scanner["mac"],
															HWAddress < 6 > (target_ap["mac"]),
															att_cfg.at("acm_trigger_count").get<int>(),
															sae_params.value());
		const path acm_txt = rs.run_folder()/ "ACM_trigger.txt";
		ofstream ofs(acm_txt);
		ofs << "ACM trigger after " << count << " frames " << "\n";
		ofs << scan_ap.to_str() << "\n";
		ofs << sae_helper::bytes_to_hex(cookie.token) << "\n";
		ofs << cookie.sta_mac << "\n";
		ofs.close();
		set_public_perms(acm_txt);
		acm_triggered = true;
	}

	string mfp = "?";
	string akm;
	if(scan_ap.rsn.has_value()){
		const uint16_t caps = scan_ap.rsn->capabilities();
		const bool mfpr = caps & (1 << 6);
		const bool mfpc = caps & (1 << 7);
		mfp = mfpr ? "REQUIRED" : (mfpc ? "Capable" : "No");

		stringstream akm_ss;
		scan_ap.print_AKMs(akm_ss, scan_ap.rsn->akm_cyphers());
		akm = akm_ss.str();
	}

	const nlohmann::json result = {
		{"ssid",          scan_ap.ssid},
		{"mac",           target_ap["mac"]},
		{"beacon_found",  scan_ap.rsn.has_value()},
		{"mfp",           mfp},
		{"akm",           akm},
		{"acm_triggered", acm_triggered},
	};
	rs.save_result(result);
}
}