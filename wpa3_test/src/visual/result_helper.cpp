#include <fstream>
#include "default.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/openwrt/openwrt_helper.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/log_util.h"
#include "observer/observers.h"
#include "observer/tshark_wrapper.h"
#include "overview/described.h"

namespace wpa3_tester::suite::helper{
using namespace std;
using namespace filesystem;
using json = nlohmann::json;

TimeWindow get_run_window(const RunStatus &rs){
	const path combined_log = rs.run_folder() / "logger" / "combined.log";
	if(!exists(combined_log)) return {};
	//first @END preferred
	return {get_tag_time(combined_log, START_tag), get_tag_time(combined_log, END_tag)};
}

optional<json> load_result_json(const path &test_folder){
	const auto result_json = test_folder / RESULT_NAME;
	if(!exists(result_json)) return nullopt;
	ifstream rf(result_json);
	return json::parse(rf);
}


// return (rogue_ap_connected, crack results)
pair<optional<bool>,optional<hostapd::CrackResult>> hostapd_mana_crack(const RunStatus &rs, vector<unique_ptr<GraphElements>> &elements){
	if(rs.actor("rogue_ap")){
		const auto mana_events = get_time_logs(rs, "rogue_ap", "Captured a WPA");
		elements.push_back(make_unique<EventLines>(mana_events, "MANA", "black"));
		string psk = hostapd::get_password(rs, "client");
		if(psk.empty()){
			psk = "password123";
			log(LogLevel::ERROR, "password for hostapd_mana not found, used default password {}", psk);
		}
		return {!mana_events.empty(),hostapd::crack_pmk_hashes(rs.run_folder()/"captured_hashes.txt", psk)};
	}
	return {nullopt, nullopt};
}

described_bool get_ap_ocv(const RunStatus &rs){
	// at least one possible source
	assert(rs.actor("attacker") || rs.actor("ap"));

	described_bool ap_ocv;
	if(exists( rs.run_folder() / "ap_hostapd.conf"))
		ap_ocv += {hostapd::get_okc(rs, "ap").value_or(false), "hostapd_conf"};
	if(const auto v = observer::tshark::ap_ocv_from_pcap(observer::get_observer_folder(rs, "tshark") / "attacker_capture.pcap"))
		ap_ocv += {*v, "pcap (beacon)"};
	return ap_ocv;
}
//TODO test
described_bool get_client_ocv(const RunStatus &rs){
	described_bool client_ocv;
	if(exists(rs.run_folder() / "client_wpa_supplicant.conf"))
		client_ocv +=  {hostapd::get_ocv(rs, "client").value_or(false), "wpa_supplicant_conf"};
	const path attacker_pcap = observer::get_observer_folder(rs, "tshark") / "attacker_capture.pcap";
	if(const auto v = observer::tshark::client_ocv_from_pcap(attacker_pcap))
		client_ocv += {*v, "pcap (probe req)"};
	return client_ocv;
}

described_str get_client_scanning(const RunStatus &rs, const TimeWindow window){
	// at least one possible source
	assert(rs.actor("client") && (rs.actor("attacker") || rs.actor("ap")));

	described_str client_scanning;
	const path attacker_pcap = observer::get_observer_folder(rs, "tshark") / "attacker_capture.pcap";
	const string sta_mac = rs.get_actor("client").get(SK::mac);

	if(const string ch = observer::tshark::client_scanning_from_pcap(attacker_pcap, sta_mac, window); !ch.empty())
		client_scanning += {ch, "attacker pcap"};

	if(const string ch = hostapd::client_scanning_from_ap_log(rs.run_folder() / "logger" / "ap.log", sta_mac); !ch.empty())
		client_scanning += {ch, "ap log"};

	return client_scanning;
}

described_str get_client_mfp(const RunStatus &rs, const TimeWindow window){
	described_str client_mfp;
	const auto wpa_config = rs.run_folder() / "client_wpa_supplicant.conf";
	if(exists(wpa_config))
		client_mfp += {hostapd::get_mfp_from_supplicant(wpa_config), "wpa_supplicant_conf"};

	const auto program_str = rs.config().at("actors").at("ap").at("setup").at("program").get<string>();

	const path ap_log = rs.run_folder() / "logger" / "ap.log";
	if(exists(ap_log)){
		if(program_str == "hostapd"){
			client_mfp += {hostapd::mfp_from_ap_log(ap_log, window), "hostapd"};
		}
		if(program_str == "openwrt"){
			client_mfp += {openwrt::mfp_from_openwrt_log(ap_log, window), "openwrt"};
		}
	}
	return client_mfp;
};

described_str get_client_WPA_support(const RunStatus &rs, const TimeWindow window){
	described_str client_WPA_support;
	const auto wpa_config = rs.run_folder() / "client_wpa_supplicant.conf";
	if(exists(wpa_config)){
		client_WPA_support += {hostapd::get_conf_value(wpa_config, {"key_mgmt"}), "wpa_supplicant_conf"};
	}
	const auto program_str = rs.config().at("actors").at("ap").at("setup").at("program").get<string>();
	const path ap_log = rs.run_folder() / "logger" / "ap.log";

	if(exists(ap_log)){
		if(program_str == "hostapd"){
			if(client_WPA_support.value().empty())
				client_WPA_support += {hostapd::client_akm_from_ap_log(ap_log, window), "hostapd"};
		}
		//TODO openwrt
	}
	return client_WPA_support;
};

described_str get_ap_WPA_support(const RunStatus &rs){
	described_str ap_WPA_support;

	const auto program_str = rs.config().at("actors").at("ap").at("setup").at("program").get<string>();
	const auto hostapd_config = rs.run_folder() / "ap_hostapd.conf";
	if(exists(hostapd_config)){
		if(program_str == "hostapd"){
			ap_WPA_support += {hostapd::get_conf_value(hostapd_config, {"wpa_key_mgmt"}), "hostapd_conf"};
		}
		if(program_str == "openwrt"){ //TODO hostapd parsing ok ?
			ap_WPA_support += {hostapd::get_conf_value(hostapd_config, {"wpa_key_mgmt"}), "openwrt"};
		}
	}
	return ap_WPA_support;
};

described_str get_conn_WPA_version(const RunStatus &rs, const TimeWindow window){
	described_str conn_WPA_version{};
	const path ap_log = rs.run_folder() / "logger" / "ap.log";
	const auto program_str = rs.config().at("actors").at("ap").at("setup").at("program").get<string>();

	if(exists(ap_log)){
		if(program_str == "hostapd"){
			conn_WPA_version += {hostapd::akm_from_ap_log(ap_log, window), "hostapd"};
		}
		if(program_str == "openwrt"){
			conn_WPA_version += {openwrt::akm_from_openwrt_log(ap_log, window), "openwrt"};
		}
	}
	const path attacker_pcap =  observer::get_observer_folder(rs, "tshark") / "attacker_capture.pcap";
	if(exists(attacker_pcap))
		conn_WPA_version += {observer::tshark::akm_from_pcap(attacker_pcap), "attacker pcap"};

	return conn_WPA_version;
}

//TODO test
described_bool get_client_disconnected(const RunStatus &rs, TimeWindow window){
	described_bool client_disconnected{};
	const string sta_mac = rs.get_actor("client").get(SK::mac);

	if(rs.get_actor("client")->is_WB()){
		const path client_log = rs.run_folder() / "logger" / "client.log";
		if(exists(client_log)){
			const auto ev = get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED", window);
			client_disconnected += {!ev.empty(), "log"};
		}
	} else {
		const path pcap_path = observer::get_observer_folder(rs, "tshark") / "attacker_capture.pcap";
		if(exists(pcap_path)){
			const string filter = "wlan.fc.type_subtype == 0x000c && wlan.sa == " + sta_mac;
			const auto ev = observer::tshark::get_tshark_events(rs, "attacker", filter, "DISCONNECTED", window);
			client_disconnected += {!ev.empty(), "pcap"};
		}
	}
	return client_disconnected;
}

}
