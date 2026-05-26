#pragma once

#include <functional>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>
#include <linux/nl80211.h>
#include <netlink/netlink.h>

#include "../config/RunStatus.h"
#include "injection_result.h"

namespace wpa3_tester{
class MonitorSocket;

// Reference frame addresses + DS flags used to build injection test frames
struct Dot11Ref{
	Tins::HWAddress<6> addr1, addr2, addr3{};
	bool from_ds = false, to_ds = false;
};

struct ProbeCapture{
	std::vector<std::vector<uint8_t>> rx_probes;
	std::vector<std::vector<uint8_t>> tx_acks;
};

enum class InterfaceType{
	Unknown,
	Loopback,
	Wifi,
	Ethernet,
	DockerBridge,
	VirtualVeth,
	VPN,
	WifiVirtualMon,
	WifiVirtualAP,
	WifiVirtualHwsim
};

struct InterfaceInfo{
	std::string name;
	std::string radio; // phyX
	InterfaceType type;
};

#include "system/wifi_channel.h"

inline std::string iface_to_string(const InterfaceType type){
	switch(type){
	case InterfaceType::Loopback: return "loopback";
	case InterfaceType::Wifi: return "wifi";
	case InterfaceType::Ethernet: return "ethernet";
	case InterfaceType::DockerBridge: return "docker/bridge";
	case InterfaceType::VirtualVeth: return "veth";
	case InterfaceType::VPN: return "vpn";
	case InterfaceType::WifiVirtualMon: return "wifi-virtual-mon";
	default: return "unknown";
	}
}

struct NlCaps{
	bool ap = false;
	bool sta = false;
	bool monitor = false;
	bool active_monitor = false;
	bool injection = false;

	bool band24 = false;
	bool band5 = false;
	bool band6 = false;

	bool wpa2_psk = false; // heuristic
	bool wpa3_sae = false;

	bool _80211n = false;  // 802.11n  (HT)
	bool _80211ac = false; // 802.11ac (VHT)
	bool _80211ax = false; // 802.11ax

	bool beacon_prot = false;
};

struct CryptoCaps{
	bool has_psk = false;
	bool has_sae = false;
	bool has_ccmp = false;
	bool has_gcmp = false;
};

constexpr uint32_t AKM_PSK = 0x000FAC02;
constexpr uint32_t AKM_SAE = 0x000FAC08;

constexpr uint32_t CIPHER_CCMP = 0x000FAC04;
constexpr uint32_t CIPHER_GCMP_256 = 0x000FAC09;

class hw_capabilities{
	static bool findSolution(const std::vector<std::string> &ruleKeys, size_t ruleIdx, const ActorCMap &rules,
							const std::vector<ActorPtr> &options,
							//only for recursive
							std::unordered_set<size_t> &usedOptions, ActorMap &currentAssignment
	);
	static int nl80211_cb(nl_msg *msg, void *arg);
	static void check_band_caps(nlattr *attrs[], NlCaps *caps);
public:
	static ActorMap check_req_options(const ActorCMap &rules, const std::vector<ActorPtr> &options);

	// run helpers
	static void run_in(const std::string &cmd, const std::filesystem::path &cwd);
	static int run_cmd(const std::vector<std::string> &argv,
		const std::optional<std::string> &netns = std::nullopt, bool print = true);
	static std::string run_cmd_output(const std::vector<std::string> &argv,
									const std::optional<std::string> &netns = std::nullopt
	);
	static void exec(const std::vector<std::string> &cmd, bool check = false);

	// git helpers
	static bool git_available();
	static void git_clone_or_pull(const std::string &url, const std::filesystem::path &dest);

	// Fill Actor_config caps for given iface (mac, driver, nl80211 capabilities)
	static void get_nl80211_caps(ActorPtr &cfg);
	static std::vector<InterfaceInfo> list_interfaces(std::optional<InterfaceType> filter = std::nullopt,
													const std::optional<std::string> &netns = std::nullopt
	);

	// check availability
	static std::string read_sysfs(const std::string &iface, const std::string &file);
	static std::string get_driver_name(const std::string &iface, const std::optional<std::string> &netns = std::nullopt);
	static std::optional<std::string> get_driver_hash(const std::string &driver_name);
	static std::optional<std::string> get_module_hash(const std::string &driver_name);
	static std::string get_phy(const std::string &iface, const std::optional<std::string> &netns);

	//format
	static int freq_to_channel(int freq);
	static int channel_to_freq(Channel ch);

	static void create_ns(const std::string &ns_name);
	static void move_to_netns(const std::string &iface, const std::string &netns);
	static std::string rand_mac();

	// working with interfaces
	static std::string get_iface(const std::string &ip_address, const std::optional<std::string> &netns);
	static Tins::HWAddress<6> get_mac_address(const std::string &iface, const std::optional<std::string> &netns);
	static std::string get_permanent_mac(const std::string &iface, const std::optional<std::string> &netns);
	static void set_mac_address(const std::string &iface, const Tins::HWAddress<6> &new_mac,
								const std::optional<std::string> &netns
	);
	static void set_channel(const std::string &iface, Channel ch, const std::optional<std::string> &netns);
	static bool set_monitor_active(const std::string &iface, const std::optional<std::string> &netns, Channel ch = {});

	static void set_iface_down(const std::string &iface, const std::optional<std::string> &netns);
	static void set_iface_up(const std::string &iface, const std::optional<std::string> &netns);
	static void set_wifi_type(std::string_view iface, nl80211_iftype type, const std::optional<std::string> &netns, const std::vector<std::string> &monitor_flags = {});

	// ----- injection utilities -----
	// Inject pdu, capture frames containing the unique label. count=0 = no limit.
	static std::vector<std::vector<uint8_t>> inject_and_capture(
		MonitorSocket &sout, MonitorSocket &sin,
		Tins::PDU &pdu, Channel ch,
		int count = 0, int retries = 1
	);
	static void flush_socket(MonitorSocket &s);
	static std::optional<std::pair<Tins::HWAddress<6>, std::string>> get_nearby_ap_addr(MonitorSocket &sin);
	static ProbeCapture capture_probe_response_ack(
		MonitorSocket &sout, MonitorSocket &sin,
		Tins::PDU &probe_req, Channel ch, int retries = 1
	);

	// ----- injection tests — return result only, no printing -----
	static InjectionTestResult test_injection_more_fragments(
		MonitorSocket &sout, MonitorSocket &sin,
		const Dot11Ref &ref, const std::string &strtype, Channel ch
	);
	// Generic field-preservation test; name identifies the subtest in the result.
	static InjectionTestResult test_packet_injection(
		MonitorSocket &sout, MonitorSocket &sin,
		Tins::PDU &pdu, const std::function<bool(const std::vector<uint8_t> &)> &test_func,
		const std::string &name, const std::string &msgfail, Channel ch
	);
	static InjectionTestResult test_injection_fields(
		MonitorSocket &sout, MonitorSocket &sin,
		const Dot11Ref &ref, const std::string &strtype, Channel ch
	);
	static InjectionTestResult test_injection_order(
		MonitorSocket &sout, MonitorSocket &sin,
		const Dot11Ref &ref, const std::string &strtype, Channel ch,
		int retries = 1
	);
	static InjectionTestResult test_injection_retrans(
		MonitorSocket &sout, MonitorSocket &sin,
		const Tins::HWAddress<6> &addr1, const Tins::HWAddress<6> &addr2, Channel ch
	);
	static InjectionTestResult test_injection_txack(
		MonitorSocket &sout, MonitorSocket &sin,
		const Tins::HWAddress<6> &dest_mac, const Tins::HWAddress<6> &own_mac, Channel ch
	);

	// Set interface to monitor mode on the given channel (down → monitor → up → set_channel)
	static void setup_injection_iface(
		const std::string &iface, Channel ch,
		const std::optional<std::string> &netns = std::nullopt
	);

	// Run the full injection test suite; returns structured results for printing.
	// peermac: fallback peer used for retrans test when no nearby AP is found.
	// testack: run retrans+txack tests (only meaningful with two distinct interfaces).
	static InjectionSuiteResult run_injection_tests(ActorPtr actor_tx, ActorPtr actor_rx, const Tins::HWAddress<6> &peermac = Tins::HWAddress<6>("00:11:22:33:44:55"), bool
													skip_mf = false, bool testack = true
	);
};
}
