#include <chrono>
#include <filesystem>
#include <vector>

#include "config/Actor_Config/ActorPtr.h"
#include "config/Actor_Config/Actor_config.h"
#include "config/global_config.h"
#include "default.h"
#include "logger/devices.h"
#include "logger/report.h"
#include "observer/dmesg_wrapper.h"
#include "observer/observers.h"
#include "system/driver_diagnostics.h"
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
	observer::dmesg::start_dmesg(rs, "scanner");

	auto scanner = rs.get_actor("scanner");
	const string iface = scanner.get(SK::iface);
	const optional<string>& netns = scanner[SK::netns];

	// ----- hw_info (modes, bands) via cache -----
	const bool use_cache = get_global_config().value("use_hw_cache", true);
	const optional<path> hw_cache = use_cache
		? optional{root_dir().parent_path() / "data" / "cache" / "scan" / "internal_iface.json"}
		: nullopt;

	scanner->set(SK::iface, iface);
	scanner->load_hw_info(hw_cache);

	/* FIXME injection tests
	MonitorSocket sock(iface);
	const auto suite = hw_capabilities::run_injection_tests(scanner, scanner,
		Tins::HWAddress<6>("00:11:22:33:44:55"), false, false);
	*/

	rs.save_actor_interface_mapping();

	// ----- live system snapshot -----
	nlohmann::json result;
	try{ result["current_mac"] = hw_capabilities::get_mac_address(iface, netns).to_string(); } catch(...){ result["current_mac"] = "n/a"; }
	try{ result["is_up"]       = netlink_helper::iface_is_up(iface, netns); }                  catch(...){ result["is_up"] = false; }
	try{ result["phy"]         = hw_capabilities::get_phy(iface, netns); }                     catch(...){ result["phy"] = "n/a"; }
	try{ result["ip_addr"]     = ip::get_ip(iface); }                                          catch(...){ result["ip_addr"] = "n/a"; }
	try{ result["iw_info"]     = hw_capabilities::run_cmd_output({"iw", "dev", iface, "info"}, netns); } catch(...){ result["iw_info"] = ""; }

	const string phy = result.value("phy", "");
	result["driver_specific"] = driver_diag::collect_driver_specific(scanner->get(SK::driver_name), phy);
	result["regulatory"]      = driver_diag::collect_regulatory(phy, netns);
	result["usb_info"]        = driver_diag::collect_usb_info(iface);

	// ----- channel switch timing -----
	{
		using namespace chrono;
		Channel test_ch{6, WifiBand::BAND_2_4, nullopt};
		const auto t0 = steady_clock::now();
		const auto ec = netlink_helper::set_channel_nl(iface, netns, test_ch);
		if(!ec) netlink_helper::wait_for_channel(iface, netns, test_ch);
		const auto ms = duration_cast<milliseconds>(steady_clock::now() - t0).count();
		result["channel_switch"]["ok"] = !ec;
		result["channel_switch"]["ms"] = ms;
		if(ec) result["channel_switch"]["error"] = ec.message();
	}

	// ----- netns round-trip timing (move + wait via nl, then delete + wait for return) -----
	try{
		using namespace chrono;
		const string test_ns = "iface_info_bench";
		hw_capabilities::create_ns(test_ns);

		const auto t0 = steady_clock::now();
		const bool moved = hw_capabilities::move_to_netns(iface, test_ns);
		// wait_for_iface_appear listens via RTMGRP_LINK in target ns — no iw polling needed
		const auto ec_appear = moved
			? netlink_helper::wait_for_iface_appear(iface, test_ns)
			: error_code{EINVAL, system_category()};
		result["netns_move"]["ok"] = !ec_appear;
		result["netns_move"]["ms"] = duration_cast<milliseconds>(steady_clock::now() - t0).count();

		const auto t2 = steady_clock::now();
		netlink_helper::delete_ns_and_wait(test_ns, vector<string>{iface});
		result["netns_return"]["ms"] = duration_cast<milliseconds>(steady_clock::now() - t2).count();
	} catch(...){
		result["netns_move"]["ok"] = false;
	}

	rs.save_result(result);

	ofstream result_txt(rs.run_folder() / "result.txt");
	result_txt << scanner->to_str();
	result_txt.close();
	set_public_perms(rs.run_folder() / "result.txt");
}

void generate_report(const RunStatus &rs){
	const auto it = rs.actors.find("scanner");
	if(it == rs.actors.end()) return;
	const auto &scanner = it->second;

	const string iface = scanner->get_or(SK::iface, "");
	if(iface.empty()) return;

	nlohmann::json result;
	try{ result = rs.load_result(); } catch(...){}

	const string current_mac = result.value("current_mac", "n/a");
	const bool   is_up       = result.value("is_up",       false);
	const string phy         = result.value("phy",         "n/a");
	const string ip_addr     = result.value("ip_addr",     "n/a");
	const string iw_info     = result.value("iw_info",     "");
	const auto   usb_info    = result.value("usb_info",    nlohmann::json{});
	const auto   regulatory  = result.value("regulatory",  nlohmann::json{});

	const string perm_mac = scanner->get_or(SK::permanent_mac, "");
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
		md << "| Driver     | " << scanner->get_or(SK::driver_name, "n/a") << " |\n";
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
		md << "| AP | " << scanner[BK::AP] << " |\n";
		md << "| STA | " << scanner[BK::STA] << " |\n";
		md << "| Monitor | " << scanner[BK::monitor] << " |\n\n";

		md << "### Frequency Bands\n\n";
		md << "| Band | Supported |\n";
		md << "|------|-----------|\n";
		md << "| 2.4 GHz | " << scanner[BK::GHz2_4] << " |\n";
		md << "| 5 GHz | " << scanner[BK::GHz5] << " |\n";
		md << "| 6 GHz | " << scanner[BK::GHz6] << " |\n\n";

		md << "### 802.11 Standards\n\n";
		md << "| Standard | Supported |\n";
		md << "|----------|-----------|\n";
		md << "| 802.11n (HT) | " << scanner[BK::w80211n] << " |\n";
		md << "| 802.11ac (VHT) | " << scanner[BK::w80211ac] << " |\n";
		md << "| 802.11ax (HE) | " << scanner[BK::w80211ax] << " |\n\n";

		md << "### Security & Features\n\n";
		md << "| Feature | Supported |\n";
		md << "|----------|-----------|\n";
		md << "| WPA2-PSK (CCMP) | " << scanner[BK::WPA_PSK] << " |\n";
		md << "| WPA3-SAE | " << scanner[BK::WPA3_SAE] << " |\n";
		md << "| MFP (BIP-CMAC-128) | " << scanner[BK::MFP] << " |\n";
		md << "| OCV | " << scanner[BK::OCV] << " |\n";
		md << "| Beacon Protection | " << scanner[BK::beacon_prot] << " |\n\n";
		md << "- **Driver (nl80211)**: `" << scanner[SK::driver_name] << "`\n";
		md << "\n";

		if (result.contains("usb_info") && !result["usb_info"].is_null()) {
			if (result["usb_info"].value("is_usb", false)) {
				md << "## USB Device\n\n";
				md << "| Field | Value |\n";
				md << "|-------|-------|\n";
				md << "| Vendor | " << usb_info.value("manufacturer", "n/a") << " (" << usb_info.value("id_vendor", "?") << ") |\n";
				md << "| Product | " << usb_info.value("product", "n/a") << " (" << usb_info.value("id_product", "?") << ") |\n";
				md << "| Serial | " << usb_info.value("serial", "n/a") << " |\n";
				md << "| Authorized | " << (usb_info.value("authorized", false) ? "yes" : "no") << " |\n\n";
			}
		}

		if(!regulatory.empty()){
			md << "## Regulatory\n\n";
			if(regulatory.contains("iw_reg_get"))
				md << "```\n" << regulatory["iw_reg_get"].get<string>() << "```\n\n";
		}

		if(result.contains("driver_specific")){
			md << "## Driver-Specific Diagnostics (debugfs)\n\n";
			md << "```json\n" << result["driver_specific"].dump(2) << "\n```\n\n";
		}

		md << "## `iw dev " << iface << " info`\n\n";
		md << "```\n" << iw_info << "```\n";
	}

	rename(rs.run_folder() / REPORT_NAME, out_path);
	cout << "\nReport written to: " << out_path << "\n";
}

void stats_attack(const RunStatus &rs){
	const auto scanner = rs.get_actor("scanner");
	report::add_device(scanner);

	generate_report(rs);
}
}
