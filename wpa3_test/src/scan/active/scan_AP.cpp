#include "scan/active/scan_AP.h"

#include <future>
#include "attacks/components/sniffer_helper.h"
#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "config/RunStatus.h"
#include "config/Actor_Config/Actor_Config_external.h"
#include "scan/active/scan_active.h"
#include "system/utils.h"
using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::scan{

void print_AKM(stringstream &ss, const RSNInformation::AKMSuites akm){
	static const map<RSNInformation::AKMSuites,string> akm_map = {
		{RSNInformation::EAP, "EAP"}, {RSNInformation::PSK, "PSK"}, {RSNInformation::EAP_FT, "EAP-FT"},
		{RSNInformation::PSK_FT, "PSK-FT"}, {RSNInformation::EAP_SHA256, "EAP-SHA256"},
		{RSNInformation::PSK_SHA256, "PSK-SHA256"}, {RSNInformation::TDLS, "TDLS"},
		{RSNInformation::SAE_SHA256, "SAE_SHA256"}, {RSNInformation::SAE_FT, "SAE-FT"},
		{RSNInformation::EAP_SHA256_FIPSB, "EAP-FIPS-B-256"}, {RSNInformation::EAP_SHA384_FIPSB, "EAP-FIPS-B-384"},
		{RSNInformation::EAP_SHA384, "EAP-SHA384"}
	};

	const auto it = akm_map.find(akm);
	if(it != akm_map.end()){
		ss << it->second;
	} else{
		char buf[20];
		sprintf(buf, "UNKNOWN(0x%08x)", static_cast<uint32_t>(akm));
		ss << buf;
	}
}

void ScanAP::print_AKMs(stringstream &ss, const RSNInformation::akm_type &akms){
	ss << "AKM Suites: ";
	for(auto &akm: akms){
		print_AKM(ss, akm);
		ss << " ";
	}
}

void print_capabilities(stringstream &ss, uint16_t caps){
	const bool mfpc = (caps & (1 << 7));   // Management Frame Protection Capable
	const bool mfpr = (caps & (1 << 6));   // Management Frame Protection Required
	const bool ocv = (caps & (1 << 10));   // Operating Channel Validation
	const bool bprot = (caps & (1 << 11)); // Beacon Protection

	ss << "--- RSN Capabilities ---\n";
	ss << "MFP: " << (mfpr ? "REQUIRED" : (mfpc ? "Capable" : "No")) << "\n";
	ss << "OCV: " << (ocv ? "Yes" : "No") << "\n";
	ss << "Beacon Protection: " << (bprot ? "Yes" : "No") << "\n";
}

string ScanAP::to_str() const{
	stringstream ss;
	ss << "SSID: " << ssid << "\n";

	if(rsn.has_value()){
		print_capabilities(ss, rsn->capabilities());
		print_AKMs(ss, rsn->akm_cyphers());
		ss << "\n";
	}

	ss << "Stations: " << stations.size() << "\n";
	for(const auto &station: stations){
		ss << "  [STATION] " << station.mac << "\n";
	}
	return ss.str();
}

static optional<unique_ptr<Dot11Beacon>> handle_beacon(PDU &pdu, ScanAP &scan_ap, const optional<path> &beacon_pcap){
	const auto *beacon = pdu.find_pdu<Dot11Beacon>();
	if(!beacon) return nullopt;

	scan_ap.ssid = beacon->ssid();
	try{ scan_ap.rsn = beacon->rsn_information(); } catch(const option_not_found &){}

	if(beacon_pcap) PacketWriter(beacon_pcap->string(), DataLinkType<RadioTap>()).write(pdu);

	return unique_ptr<Dot11Beacon>(beacon->clone());
}

unique_ptr<Dot11Beacon> RSN_scan(const string &interface, const int timeout_sec, ScanAP &scan_ap,
								const optional<path> &beacon_pcap
){
	const string filter = "(type mgt subtype beacon or type mgt subtype probe-resp) and ether addr2 " + scan_ap.bssid;

	auto result = components::poll_sniffer_pdu<unique_ptr<Dot11Beacon>>(
		[&](PDU &pdu){ return handle_beacon(pdu, scan_ap, beacon_pcap); }, interface, filter, seconds(timeout_sec));

	if(auto *val = get_if<unique_ptr<Dot11Beacon>>(&result)) return std::move(*val);
	return nullptr;
}

static void apply_rsn_caps(const Dot11Beacon &beacon, Actor_Config_external &cfg){
	try{
		const auto rsn = beacon.rsn_information();
		const uint16_t caps = rsn.capabilities();
		cfg.set(BK::MFP,         static_cast<bool>(caps & (1u << 7)));
		cfg.set(BK::OCV,         static_cast<bool>(caps & (1u << 10)));
		cfg.set(BK::beacon_prot, static_cast<bool>(caps & (1u << 11)));

		bool wpa2_psk = false, wpa3_sae = false;
		for(const auto &akm: rsn.akm_cyphers()){
			if(akm == RSNInformation::PSK || akm == RSNInformation::PSK_FT || akm == RSNInformation::PSK_SHA256)
				wpa2_psk = true;
			if(akm == RSNInformation::SAE_SHA256 || akm == RSNInformation::SAE_FT)
				wpa3_sae = true;
		}
		cfg.set(BK::WPA_PSK,  wpa2_psk);
		cfg.set(BK::WPA3_SAE, wpa3_sae);
	} catch(...){}
}

void fill_actor_caps_from_beacon(PDU &pdu, Actor_Config_external &cfg){
	const auto *beacon = pdu.find_pdu<Dot11Beacon>();
	if(!beacon) return;

	cfg.set(SK::mac, beacon->addr2().to_string());
	try{ cfg.set(SK::ssid, beacon->ssid()); } catch(...){}

	apply_radiotap(pdu, cfg);

	// Channel fallback from DS Parameter Set if RadioTap had no frequency
	if(!cfg[SK::channel].has_value()){
		try{ cfg.set(SK::channel, to_string(beacon->ds_parameter_set())); } catch(...){}
	}

	apply_rsn_caps(*beacon, cfg);
	apply_ht_vht_he(*beacon, cfg);

	cfg.set(BK::AP,      true);
	cfg.set(BK::STA,     false);
	cfg.set(BK::managed, false);
	cfg.set(BK::monitor, false);
}

Actor_Config_external scan_ap_actor(const string &iface, const string &bssid, const int timeout_sec){
	Actor_Config_external cfg;
	cfg.set(SK::mac, bssid);

	const string filter = "(type mgt subtype beacon or type mgt subtype probe-resp) and ether addr2 " + bssid;
	components::poll_sniffer_pdu<monostate>(
		[&](PDU &pdu) -> optional<monostate>{
			fill_actor_caps_from_beacon(pdu, cfg);
			return monostate{};
		},
		iface, filter, seconds(timeout_sec)
	);

	log(LogLevel::INFO, "scan_ap_actor {}: {}", bssid, cfg.to_str());
	return cfg;
}

}