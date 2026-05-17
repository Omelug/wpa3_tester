#include "attacks/scan/iface_info.h"

#include <filesystem>
#include <fstream>
#include <sstream>

#include "attacks/mc_mitm/MonitorSocket.h"
#include "config/ActorPtr.h"
#include "config/Actor_config.h"
#include "observer/tshark_wrapper.h"
#include "system/hw_capabilities.h"
#include "system/hw_info.h"
#include "system/injection_result.h"
#include "system/ip.h"
#include "system/netlink_helper.h"

namespace wpa3_tester::iface_info{
using namespace std;
using namespace filesystem;

static string bool_cell(const optional<bool> v){
    if(!v.has_value()) return "?";
    return v.value() ? "yes" : "no";
}

void run_attack(RunStatus &rs){
	rs.start_observers();

    const string iface  = rs.get_actor("scanner")["iface"];
    const int    ch_num = rs.config().at("attack_config").at("channel").get<int>();
    const Channel channel{ch_num, WifiBand::BAND_2_4};

    // ----- basic info -----
    const string current_mac = hw_capabilities::get_mac_address(iface, nullopt).to_string();
    const bool   is_up       = netlink_helper::iface_is_up(iface, nullopt);
    const string phy         = hw_capabilities::get_phy(iface, nullopt);
    const string ip_addr     = [&]() -> string {
        try{ return ip::get_ip(iface); } catch(...){ return "n/a"; }
    }();
    const string iw_info = hw_capabilities::run_cmd_output({"iw", "dev", iface, "info"});

    // ----- hw_info (modes, bands, injection self-test) via cache -----
    const path hw_cache = path(PROJECT_ROOT_DIR).parent_path() / "data" / "scan" / "internal_iface.json";
	
	auto scanner = rs.get_actor("scanner");
	scanner->set(SK::iface, iface);
    scanner->load_hw_info(hw_cache);

    // ----- injection tests -----
    cout << "Setting up " << iface << " as monitor on channel " << ch_num << "...\n";
    MonitorSocket sock(iface);
    const auto suite = hw_capabilities::run_injection_tests(
        sock, iface,
        sock,
        channel,
        Tins::HWAddress<6>("00:11:22:33:44:55"),
        /*skip_mf=*/false,
        /*testack=*/false
    );

	//TODO scan to  Actor_coinfig
    // ----- build markdown -----
    ostringstream md;
    md << "# Interface Report: " << iface << "\n\n";
    md << "## Basic Info\n\n";
    md << "| Property | Value |\n";
    md << "|----------|-------|\n";
    md << "| Name       | `" << iface << "` |\n";
    md << "| PHY        | " << (phy.empty() ? "n/a" : phy) << " |\n";
    md << "| Driver     | " << scanner.get(SK::driver_name) << " |\n";
    md << "| State      | " << (is_up ? "UP" : "DOWN") << " |\n";
    md << "| IP Address | " << ip_addr << " |\n\n";

    md << "## MAC Addresses\n\n";
    md << "| Type | Address |\n";
    md << "|------|---------|\n";
    md << "| Current (active) | `" << current_mac << "` |\n";

	auto perm_mac = scanner->get(SK::permanent_mac);
    md << "| Permanent (static) | `" << perm_mac << "` |\n\n";

    if(!perm_mac.empty() && perm_mac != current_mac)
        md << "> **Note:** MAC address is currently spoofed (differs from permanent).\n\n";

    md << "## nl80211 Capabilities\n\n";

    md << "### Interface Modes\n\n";
    md << "| Mode | Supported |\n";
    md << "|------|-----------|\n";
    md << "| AP | " << bool_cell(scanner[BK::AP]) << " |\n";
    md << "| STA | " << bool_cell(scanner[BK::STA]) << " |\n";
    md << "| Monitor | " << bool_cell(scanner[BK::monitor]) << " |\n\n";

    md << "### Frequency Bands\n\n";
    md << "| Band | Supported |\n";
    md << "|------|-----------|\n";
    md << "| 2.4 GHz | " << bool_cell(scanner[BK::GHz2_4]) << " |\n";
    md << "| 5 GHz | " << bool_cell(scanner[BK::GHz5]) << " |\n";
    md << "| 6 GHz | " << bool_cell(scanner[BK::GHz6]) << " |\n\n";

    md << "### 802.11 Standards\n\n";
    md << "| Standard | Supported |\n";
    md << "|----------|-----------|\n";
    md << "| 802.11n (HT) | " << bool_cell(scanner[BK::w80211n]) << " |\n";
    md << "| 802.11ac (VHT) | " << bool_cell(scanner[BK::w80211ac]) << " |\n";
    md << "| 802.11ax (HE) | " << bool_cell(scanner[BK::w80211ax]) << " |\n\n";

    md << "### Security & Features\n\n";
    md << "| Feature | Supported |\n";
    md << "|----------|-----------|\n";

    if(scanner[SK::driver_name].has_value())
        md << "- **Driver (nl80211)**: `" << scanner[SK::driver_name].value() << "`\n";
    if(scanner[SK::mac].has_value())
        md << "- **MAC (nl80211)**: `" << scanner[SK::mac].value() << "`\n";
    md << "\n";

    md << "## `iw dev " << iface << " info`\n\n";
    md << "```\n" << iw_info << "```\n";

    md << print_injection_result(suite);

    // ----- write report -----
    string mac_slug = perm_mac.empty() ? current_mac : perm_mac;
    ranges::replace(mac_slug, ':', '_');

    create_directories(rs.run_folder());
    const path out_path = rs.run_folder() / ("iface_report_" + mac_slug + ".md");
    ofstream f(out_path);
    if(!f.is_open()) throw runtime_error("Cannot open output file: " + out_path.string());
    f << md.str();
    f.close();

    cout << "\nReport written to: " << out_path << "\n";
}
}
