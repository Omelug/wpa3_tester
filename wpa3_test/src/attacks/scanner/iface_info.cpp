#include <filesystem>

#include "config/Actor_Config/ActorPtr.h"
#include "config/Actor_Config/Actor_config.h"
#include "default.h"
#include "logger/report.h"
#include "system/hw_capabilities.h"
#include "system/hw_info.h"
#include "system/ip.h"
#include "system/netlink_helper.h"
#include "system/utils.h"

namespace wpa3_tester::iface_info{
using namespace std;
using namespace filesystem;


void run_attack(RunStatus &rs){
	rs.start_observers();

	const string iface = rs.get_actor("scanner")["iface"];

	// ----- hw_info (modes, bands) via cache -----
	const path hw_cache = path(PROJECT_ROOT_DIR).parent_path() / "data" / "cache" / "scan" / "internal_iface.json";

	auto scanner = rs.get_actor("scanner");
	scanner->set(SK::iface, iface);
	scanner->load_hw_info(hw_cache);

	/* FIXME injection tests
    MonitorSocket sock(iface);
    const auto suite = hw_capabilities::run_injection_tests(scanner, scanner,
		Tins::HWAddress<6>("00:11:22:33:44:55"), false, false);
	*/

	rs.save_actor_interface_mapping();
}

void generate_report(const RunStatus &rs){
	const auto it = rs.actors.find("scanner");
	if(it == rs.actors.end()) return;
	const auto &scanner = it->second;

	const string iface = scanner->get(SK::iface);
	if(iface.empty()) return;

	const string current_mac = hw_capabilities::get_mac_address(iface, nullopt).to_string();
	const bool is_up = netlink_helper::iface_is_up(iface, nullopt);
	const string phy = hw_capabilities::get_phy(iface, nullopt);
	const string ip_addr = [&]() -> string {
		try{ return ip::get_ip(iface); } catch(...){ return "n/a"; }
	}();
	const string iw_info = hw_capabilities::run_cmd_output({"iw", "dev", iface, "info"});

	string perm_mac = scanner->get(SK::permanent_mac);
	string mac_slug = perm_mac.empty() ? current_mac : perm_mac;
	ranges::replace(mac_slug, ':', '_');

	create_public_dirs(rs.run_folder());
	const path out_path = rs.run_folder() / ("iface_report_" + mac_slug + ".md");

	{
		report::ReportGuard md(rs.run_folder());
		if(!md) return;

		md << "# Interface Report: " << iface << "\n\n";
		md << "## Basic Info\n\n";
		md << "| Property | Value |\n";
		md << "|----------|-------|\n";
		md << "| Name       | `" << iface << "` |\n";
		md << "| PHY        | " << phy << " |\n";
		md << "| Driver     | " << scanner->get(SK::driver_name) << " |\n";
		md << "| State      | " << (is_up ? "UP" : "DOWN") << " |\n";
		md << "| IP Address | " << ip_addr << " |\n\n";

		md << "## MAC Addresses\n\n";
		md << "| Type | Address |\n";
		md << "|------|---------|\n";
		md << "| Current (active) | `" << current_mac << "` |\n";
		md << "| Permanent (static) | `" << perm_mac << "` |\n\n";

		if(!perm_mac.empty() && perm_mac != current_mac)
			md << "> **Note:** MAC address is currently spoofed (differs from permanent).\n\n";

		md << "## nl80211 Capabilities\n\n";

		md << "### Interface Modes\n\n";
		md << "| Mode | Supported |\n";
		md << "|------|-----------|\n";
		md << "| AP | " << (*scanner)[BK::AP] << " |\n";
		md << "| STA | " << (*scanner)[BK::STA] << " |\n";
		md << "| Monitor | " << (*scanner)[BK::monitor] << " |\n\n";

		md << "### Frequency Bands\n\n";
		md << "| Band | Supported |\n";
		md << "|------|-----------|\n";
		md << "| 2.4 GHz | " << (*scanner)[BK::GHz2_4] << " |\n";
		md << "| 5 GHz | " << (*scanner)[BK::GHz5] << " |\n";
		md << "| 6 GHz | " << (*scanner)[BK::GHz6] << " |\n\n";

		md << "### 802.11 Standards\n\n";
		md << "| Standard | Supported |\n";
		md << "|----------|-----------|\n";
		md << "| 802.11n (HT) | " << (*scanner)[BK::w80211n] << " |\n";
		md << "| 802.11ac (VHT) | " << (*scanner)[BK::w80211ac] << " |\n";
		md << "| 802.11ax (HE) | " << (*scanner)[BK::w80211ax] << " |\n\n";

		md << "### Security & Features\n\n";
		md << "| Feature | Supported |\n";
		md << "|----------|-----------|\n";
		md << "| WPA2-PSK (CCMP) | " << (*scanner)[BK::WPA_PSK] << " |\n";
		md << "| WPA3-SAE | " << (*scanner)[BK::WPA3_SAE] << " |\n";
		md << "| MFP (BIP-CMAC-128) | " << (*scanner)[BK::MFP] << " |\n";
		md << "| OCV | " << (*scanner)[BK::OCV] << " |\n";
		md << "| Beacon Protection | " << (*scanner)[BK::beacon_prot] << " |\n\n";

		if((*scanner)[SK::driver_name].has_value())
			md << "- **Driver (nl80211)**: `" << (*scanner)[SK::driver_name].value() << "`\n";
		md << "\n";

		md << "## `iw dev " << iface << " info`\n\n";
		md << "```\n" << iw_info << "```\n";
	}

	rename(rs.run_folder() / REPORT_NAME, out_path);
	cout << "\nReport written to: " << out_path << "\n";
}

void stats_attack(const RunStatus &rs){
	generate_report(rs);
}
}
