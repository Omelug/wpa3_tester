#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"
#include <fstream>
#include <unistd.h>
#include <attacks/components/sniffer_helper.h>
#include <tins/hw_address.h>

#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "logger/log.h"
#include "pcap/pcap.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::cookie_guzzler{
optional<dos_helpers::SAEPair> capture_sae_commit(const HWAddress<6> &ap_mac,
												const int timeout_sec, pcap_t *handle, const string &iface
){
	char errbuf[PCAP_ERRBUF_SIZE];

	const bool owns = (handle == nullptr);
	if(owns){
		handle = pcap_open_live(iface.c_str(), 2000, 1, 100, errbuf);
		if(!handle) throw run_err("pcap_open_live failed: " + string(errbuf));
		pcap_setnonblock(handle, 1, errbuf);
	}
	auto guard = unique_ptr<pcap_t, void(*)(pcap_t*)>(owns ? handle : nullptr,
		[](pcap_t *h){ if(h) pcap_close(h); });

	const string filter_str = "wlan type mgt subtype auth and wlan addr2 " + ap_mac.to_string();
	bpf_program fp{};
	if(pcap_compile(handle, &fp, filter_str.c_str(), 1, PCAP_NETMASK_UNKNOWN) == 0)
		pcap_setfilter(handle, &fp);
	pcap_freecode(&fp);

	auto result = components::poll_sniffer<dos_helpers::SAEPair>(
		handle, milliseconds(timeout_sec * 1000),
		[](const uint8_t *packet, uint32_t caplen) -> optional<dos_helpers::SAEPair> {
			if(caplen < 10){
				log(LogLevel::DEBUG, "Packet too short: {}", caplen);
				return nullopt;
			}

			log(LogLevel::DEBUG, "Hex: {:02x} {:02x} {:02x} {:02x}", packet[0], packet[1], packet[2], packet[3]);

			//if (dumper) pcap_dump(reinterpret_cast<u_char*>(dumper), header, packet);
			if(auto frame = dos_helpers::parse_sae_commit({packet, packet + caplen})){
				log(LogLevel::DEBUG, "Captured SAE commit, scalar size: {}", frame->scalar.size());
				return frame;
			}
			return nullopt;
		},
		iface
	);

	if(holds_alternative<dos_helpers::SAEPair>(result))
		return get<dos_helpers::SAEPair>(std::move(result));
	return nullopt;
}

void start_wpa_supplicant(RunStatus &rs, const string &iface, const string &conf_path, const string &pid_file){
	if(rs.process_manager.process_exists("get_commit")){ rs.process_manager.stop("get_commit"); }
	if(filesystem::exists(pid_file)){ filesystem::remove(pid_file); }

	// Clean up stale socket
	const string socket = "/var/run/wpa_supplicant/" + iface;
	if(filesystem::exists(socket)) filesystem::remove(socket);

	log(LogLevel::INFO, "Run wpa_supplicant to get handshake values...");
	rs.process_manager.run("get_commit", {"wpa_supplicant", "-B", "-i", iface, "-c", conf_path, "-P", pid_file});
}

string create_wpa_supplicant_config(const string &ssid){
	string conf_path = "/tmp/wpa3_guzzler_temp" + ssid + ".conf";
	ofstream conf(conf_path);

	if(conf.is_open()){
		conf << "ctrl_interface=/var/run/wpa_supplicant\n";
		conf << "update_config=1\n";
		conf << "network={\n";
		conf << "    ssid=\"" << ssid << "\"\n";
		conf << "    key_mgmt=SAE\n";
		conf << "    sae_password=\"anything123\"\n"; // password doesnt matter
		conf << "    ieee80211w=2\n";
		conf << "}\n";
		conf.close();
		set_public_perms(conf_path);
	}
	return conf_path;
}

optional<dos_helpers::SAEPair> get_commit_values(RunStatus &rs, const string &iface, const string &sniff_iface,
												const string &ssid, const HWAddress<6> &ap_mac, const int timeout,
												pcap_t *handler
){
	if(iface == sniff_iface) throw invalid_argument("Interface names do cant be same");
	const string pid_file = "/tmp/wpa_supplicant_get_commit_values.pid";
	const string conf_path = create_wpa_supplicant_config(ssid);
	start_wpa_supplicant(rs, iface, filesystem::absolute(conf_path), pid_file);
	optional<dos_helpers::SAEPair> sae_params = capture_sae_commit(ap_mac, timeout, handler, sniff_iface);
	if(handler != nullptr) pcap_close(handler);
	rs.process_manager.stop("get_commit");
	filesystem::remove(pid_file);
	filesystem::remove(conf_path);
	return sae_params;
}
}