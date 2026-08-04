#pragma once
#include "config/RunStatus.h"
#include <optional>
#include <filesystem>

namespace wpa3_tester::scan{
class ScanAP{
public:
	std::string ssid;
	Tins::HWAddress<6> bssid;
	Tins::Dot11Beacon beacon;
	std::optional<Tins::RSNInformation> rsn;
	std::set<Tins::HWAddress<6>> stations;

	static void print_AKMs(std::stringstream &ss, const Tins::RSNInformation::akm_type &akms);
	static void print_AKM(std::stringstream &ss, Tins::RSNInformation::AKMSuites akm);
	[[nodiscard]] std::string to_str() const;
	void load(const std::unique_ptr<Tins::Dot11Beacon> & beacon);
};

std::optional<std::unique_ptr<Tins::Dot11Beacon>> handle_beacon(Tins::PDU &pdu, const Tins::HWAddress<6> &ap_mac,
																const std::optional<std::filesystem::path> &beacon_pcap
);

std::unique_ptr<Tins::Dot11Beacon> RSN_scan(const std::string &interface, int timeout_sec, const Tins::HWAddress<6> &ap_mac,
											const std::optional<std::filesystem::path> &beacon_pcap = std::nullopt
);

//TODO scan
// check ACm threshold
// check SAE GROUPS
}