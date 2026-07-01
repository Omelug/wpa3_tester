#include "ex_program/external_actors/openwrt/OpenWrtConn.h"
#include "config/global_config.h"
#include "config/Actor_Config/Actor_Config_external.h"
#include "logger/error_log.h"
#include "observer/observers.h"
#include "system/hw_capabilities.h"
#include "system/ip.h"

namespace wpa3_tester{
using namespace std;

void OpenWrtConn::check_req(const nlohmann::json &config, const string &actor_name){
	const auto &setup_node = config.at("actors").at(actor_name).at("setup");
	if(!setup_node.contains("ex_WB_programs")){ return; }
	auto ex_WB_programs = setup_node.at("ex_WB_programs");
	for(const auto &req_name: ex_WB_programs){

		const string pkg = req_name.get<string>();
		if(pkg == "remote_injector"){
			ensure_inject_binary();
			continue;
		}

		int ret = 0;
		exec("opkg status " + pkg + " | grep -q 'Status:.*installed'", false, &ret);
		if(ret == 0) continue;

		exec("opkg install " + pkg, false, &ret);
		if(ret){
			exec("opkg update", false, &ret); //FIXME hardcoced conflict packages
			exec("opkg remove wpad wpad-wolfssl wpad-basic wpad-basic-wolfssl 2>/dev/null", false, &ret);
			exec("opkg install " + pkg, false, &ret);
			if(ret){ throw config_err("Cannot install " + pkg + " after opkg update"); }
			exec("reboot", false, &ret);
			throw config_err("Rebooting router to activate " + pkg + " — re-run the test after reboot");
		}
	}
}

string OpenWrtConn::wait_for_ifname(const string &section) const{
	constexpr int retries = 15;
	const string cmd = "ubus call network.wireless status | " "jsonfilter -e \"$.*.interfaces[@.section='" + section +
			"'].ifname\"";

	for(int i = 0; i < retries; i++){
		string ifname = exec(cmd);
		erase(ifname, '\n');
		erase(ifname, '\r');

		if(!ifname.empty()){
			int ret = 0;
			exec("ls /sys/class/net/" + ifname + " >/dev/null 2>&1", false, &ret);

			if(ret == 0){
				log(LogLevel::DEBUG, "Found ifname: {} for section {}", ifname, section.c_str());
				return ifname;
			}
		}

		log(LogLevel::DEBUG, "Waiting for ifname of {} ({}/{})", section, i + 1, retries);
		this_thread::sleep_for(chrono::seconds(1));
	}
	throw ex_conn_err("ifname not available for section: " + section);
}

void OpenWrtConn::forward_internet(const string &remote_ip) const{
	hw_capabilities::run_cmd({"bash", "-c", "echo 1 | tee /proc/sys/net/ipv4/ip_forward"});
	auto internet_iface = get_global_config().at("internet_interface").get<string>();

	// default netns
	const string local_iface = hw_capabilities::get_iface(remote_ip, nullopt);
	hw_capabilities::run_cmd({"iptables", "-A", "FORWARD", "-i", local_iface, "-o", internet_iface, "-j", "ACCEPT"});
	hw_capabilities::run_cmd({
		"iptables", "-A", "FORWARD", "-i", internet_iface, "-o", local_iface, "-m", "state", "--state",
		"RELATED,ESTABLISHED", "-j", "ACCEPT"
	});

	const string local_ip = ip::get_ip(local_iface);

	exec("uci set network.lan.gateway=" + local_ip);
	exec("uci set network.lan.dns=8.8.8.8");
	exec("uci commit network");
	exec("/etc/init.d/network restart");
}

void OpenWrtConn::time_fix() const{
	exec("/etc/init.d/sysntpd stop");
	int ret = 0;
	exec("ntpd -q -n -p 0.openwrt.pool.ntp.org", false, &ret);
	if(ret != 0) throw ex_conn_err("Failed to sync time with NTP");
	exec("/etc/init.d/sysntpd start");
}

void OpenWrtConn::setup_iface(const string &radio_name, ActorPtr &actor, const nlohmann::json &config){
	const auto j = nlohmann::json::parse(exec("wifi status 2>/dev/null"));

	if(!j.contains(radio_name)) throw ex_conn_err("Radio not found: " + radio_name);
	const auto &radio = j.at(radio_name);

	// enable disabled radio
	if(radio.value("disabled", false)) exec("uci set wireless." + radio_name + ".disabled=0");

	// find existing section or create new
	string section;
	for(const auto &iface: radio.at("interfaces")){
		if(iface.contains("section")){
			section = iface.at("section").get<string>();
			break; // reuse existing
		}
	}
	if(section.empty()) section = "wpa3_tester_" + radio_name; // create new
	log(LogLevel::DEBUG, "Setting up wifi-iface {} for {}", section, radio_name);

	exec("uci delete wireless." + section + "_open 2>/dev/null; true");
	exec("uci delete wireless." + section + " 2>/dev/null; true");
	exec("uci set wireless." + section + "=wifi-iface");
	exec("uci set wireless." + section + ".device=" + radio_name);

	const auto program_config = config.at("actors").at(actor[SK::actor_name].value()).at("setup").at("program_config");
	const string mode = program_config.value("mode", "ap");

	if(mode == "monitor"){
		setup_monitor_iface(radio_name, actor, program_config);
		return;
	}

	if(program_config.value("owe_transition_mode", false)){
		const string open_ssid = program_config.at("open_ssid").get<string>();
		const string owe_ssid  = program_config.at("owe_ssid").get<string>();
		const string open_section = section + "_open";

		static const set<string> trans_skip  = {"owe_transition_mode", "open_ssid", "owe_ssid", "mode"};
		static const set<string> owe_bss_only = {"ieee80211w"};

		auto apply_keys = [&](const string &sec, bool skip_owe_only){
			for(const auto &[key, value]: program_config.items()){
				if(trans_skip.contains(key)) continue;
				if(skip_owe_only && owe_bss_only.contains(key)) continue;
				string v;
				if(value.is_string())      v = value.get<string>();
				else if(value.is_number()) v = value.dump();
				else continue;
				exec("uci set wireless." + sec + "." + key + "='" + v + "'");
			}
		};

		// OWE BSS (hidden)
		exec("uci delete wireless." + section + " 2>/dev/null; true");
		exec("uci set wireless." + section + "=wifi-iface");
		exec("uci set wireless." + section + ".device=" + radio_name);
		apply_keys(section, false);
		exec("uci set wireless." + section + ".ssid='" + owe_ssid + "'");
		exec("uci set wireless." + section + ".encryption=owe");
		exec("uci set wireless." + section + ".mode=ap");
		exec("uci set wireless." + section + ".hidden=1");
		exec("uci set wireless." + section + ".network=lan");

		// Open BSS
		exec("uci delete wireless." + open_section + " 2>/dev/null; true");
		exec("uci set wireless." + open_section + "=wifi-iface");
		exec("uci set wireless." + open_section + ".device=" + radio_name);
		apply_keys(open_section, true);
		exec("uci set wireless." + open_section + ".ssid='" + open_ssid + "'");
		exec("uci set wireless." + open_section + ".encryption=none");
		exec("uci set wireless." + open_section + ".mode=ap");
		exec("uci set wireless." + open_section + ".network=lan");

		exec("uci commit wireless");
		exec("wifi down " + radio_name + " 2>/dev/null; wifi up " + radio_name);

		// get real ifnames to link the two BSSes
		const string owe_ifname  = wait_for_ifname(section);
		const string open_ifname = wait_for_ifname(open_section);
		exec("uci set wireless." + section + ".owe_transition_ifname=" + open_ifname);
		exec("uci set wireless." + open_section + ".owe_transition_ifname=" + owe_ifname);
		exec("uci commit wireless");
		exec("wifi down " + radio_name + " 2>/dev/null; wifi up " + radio_name);
		wait_for_ifname(section);

		actor->set(SK::iface, owe_ifname);
		actor->set(SK::mac, get_mac_address(owe_ifname));
		actor->set(SK::radio, radio_name);
		return;
	}

	for(auto &[key, value]: program_config.items()){
		string v;
		if(value.is_string())      v = value.get<string>();
		else if(value.is_number()) v = value.dump();
		else continue;
		exec(string("uci set wireless.").append(section).append(".").append(key).append("='").append(v).append("'"));
	}
	exec("uci set wireless." + section + ".network=lan");

	exec("uci commit wireless");
	exec("wifi down " + radio_name + " 2>/dev/null; wifi up " + radio_name);

	// wait for ifname and store in actor
	const string ifname = wait_for_ifname(section);
	actor->set(SK::iface, ifname);
	actor->set(SK::mac, get_mac_address(ifname));
	actor->set(SK::radio, radio_name);
}

void OpenWrtConn::setup_monitor_iface(const string &radio_name, const ActorPtr &actor, const nlohmann::json &program_config) const{
	// Bypass UCI/wifi for monitor mode — wpa_supplicant fights with netifd and prevents interface creation.
	// Use iw directly to create the monitor interface on the phy.
	const string phy = "phy" + radio_name.substr(5); // "radio0" → "phy0"
	const string ifname = phy + "-mon0";

	exec("wifi down " + radio_name + " 2>/dev/null; true");
	// delete ALL vifs on this phy — driver limits concurrent interfaces
	exec("for dev in $(iw dev | awk '/phy#" + phy.substr(3) + "/{p=1} p && /Interface/{print $2; p=0}'); do iw dev $dev del 2>/dev/null; done; true");
	exec("iw phy " + phy + " interface add " + ifname + " type monitor");

	if(program_config.contains("channel")){
		const string ch = program_config.at("channel").is_string()
			? program_config.at("channel").get<string>()
			: to_string(program_config.at("channel").get<int>());
		const string htmode = program_config.value("htmode", "HT20");
		exec("iw dev " + ifname + " set channel " + ch + " " + htmode);
	}

	exec("ip link set " + ifname + " up");

	actor->set(SK::iface, ifname);
	actor->set(SK::mac, get_mac_address(ifname));
	actor->set(SK::radio, radio_name);
}

bool OpenWrtConn::connect(const ActorPtr &actor){
	const bool success = ExternalConn::connect(actor);
	if(success){
		forward_internet(actor.get(SK::whitebox_ip));
		time_fix();
	}
	return success;
}

vector<string> OpenWrtConn::get_radio_list(){
	const string output = exec("wifi status 2>/dev/null");
	const auto j = nlohmann::json::parse(output);
	vector<string> radios;
	for(const auto &[radio_name, radio]: j.items()){
		radios.push_back(radio_name);
	}
	return radios;
}

void OpenWrtConn::set_monitor_mode(const string &iface) const{
	exec("wifi down"); // stop hostapd/supplicant
	ExternalConn::set_monitor_mode(iface);
}

void OpenWrtConn::set_managed_mode(const string &iface) const{
	ExternalConn::set_managed_mode(iface);
	exec("wifi up"); // restart hostapd/supplicant
}

auto OpenWrtConn::set_ip(const string &iface, const string &ip_addr) const->void{
	const auto j = nlohmann::json::parse(exec("wifi status 2>/dev/null"));

	string iface_safe = iface;
	ranges::replace(iface_safe, '-', '_');
	const string wpa3_section = "wpa3_tester_" + iface_safe;

	int rc;
	exec("uci get network." + wpa3_section + " 2>/dev/null", false, &rc);
	if(rc != 0){
		exec("uci set network." + wpa3_section + "=interface");
		exec("uci set network." + wpa3_section + ".proto=static");

		for(const auto &[radio_name, radio]: j.items()){
			for(const auto &wifi_iface: radio.at("interfaces")){
				if(wifi_iface.value("ifname", "") == iface){
					const string wifi_section = wifi_iface.at("section").get<string>();
					exec(format("uci set wireless.{}.network={}", wifi_section, wpa3_section));
				}
			}
		}
		exec("uci commit wireless");
	}

	exec("uci set network." + wpa3_section + ".ipaddr=" + ip_addr);
	exec("uci set network." + wpa3_section + ".netmask=255.255.255.0");
	exec("uci commit network");
	exec("/etc/init.d/network restart");
}

string OpenWrtConn::get_radio(const string &iface) const{
	return exec("uci show wireless | grep " + iface + " | cut -d. -f2");
}

string OpenWrtConn::get_wifi_iface_section(const string &iface) const{
	const auto j = nlohmann::json::parse(exec("ubus call network.wireless status 2>/dev/null"));

	for(const auto &[radio_name, radio]: j.items()){
		if(!radio.contains("interfaces")) continue;
		for(const auto &wifi_iface: radio.at("interfaces")){
			if(wifi_iface.value("ifname", "") == iface && wifi_iface.contains("section"))
				return wifi_iface.at("section").get<string>();
		}
	}
	throw ex_conn_err("No section found for iface: " + iface);
}

// -------------------------------------------

void OpenWrtConn::setup_ap(const RunStatus &rs, ActorPtr &actor){
	nlohmann::json program_config = rs.config().at("actors").at(actor.get(SK::actor_name)).at("setup").at(
		"program_config");
	const string ssid_key = program_config.value("owe_transition_mode", false) ? "owe_ssid" : "ssid";
	actor->set(SK::ssid, program_config.at(ssid_key).get<string>());
	actor->set(SK::channel, to_string(program_config.at("channel").get<int>()));

	// radio level keys
	static const set<string> radio_keys = {
		"channel", "htmode", "txpower", "country", "beacon_int", "noscan", "disabled", "log_level", "transition_disable"
	};
	const string wifi_iface = actor.get(SK::iface);

	// reset section to avoid stale options from previous test runs bleeding in
	exec("uci delete wireless." + wifi_iface);
	exec("uci set wireless." + wifi_iface + "=wifi-iface");
	exec("uci set wireless." + actor.get(SK::radio) + ".disabled=0");
	exec("uci set wireless." + wifi_iface + ".device=" + actor.get(SK::radio));
	for(const auto &[key, val]: program_config.items()){
		const string value = val.is_string() ? val.get<string>() : val.dump();

		if(key == "eap_user_file"){
			const filesystem::path local = rs.config_path().parent_path() / value;
			constexpr string_view remote = "/etc/hostapd.eap_user";
			upload_file(local, remote);
			exec(format("uci set wireless.{}.eap_user_file={}", wifi_iface, remote));
		} else if(radio_keys.contains(key)){
			exec(format("uci set wireless.{}.{}={}", actor.get(SK::radio), key, value));
		} else{
			exec(format("uci set wireless.{}.{}={}", wifi_iface, key, value));
		}
	}
	exec("uci commit wireless");
	int ret = 0;
	exec("wifi reload 2>&1", false, &ret);
	if(ret != 0) log(LogLevel::WARNING, "wifi reload returned non-zero ({}) after setup_ap — AP may not be configured correctly", ret);
}

void OpenWrtConn::logger(RunStatus &rs, const string &actor_name){
	constexpr int port = 5140;
	const ActorPtr &ap_actor = rs.get_actor(actor_name);
	const string remote_ip = ap_actor[SK::whitebox_ip].value();
	const string kali_ip = ip::get_ip(hw_capabilities::get_iface(remote_ip, nullopt));
	rs.process_manager.run(actor_name, {"socat", "TCP-LISTEN:" + to_string(port) + ",reuseaddr", "STDOUT"});
	exec("logread -f -l 100 -r " + kali_ip + " " + to_string(port) + " & echo $! > /tmp/logread_" + actor_name +
		".pid");

	const auto ap = rs.get_actor(actor_name);
	ap->conn->on_disconnect([this, actor_name](){
		exec("kill $(cat /tmp/logread_" + actor_name + ".pid); rm /tmp/logread_" + actor_name + ".pid");
	});
}

void OpenWrtConn::get_hw_capabilities(const ActorPtr &actor){
	const string phy = "phy" + actor.get(SK::radio).substr(5);
	int ret = 0;
	const string output = exec("iw phy " + phy + " info", false, &ret);
	if(ret != 0) throw ex_conn_err("Failed to get hw capabilities for phy {}:{}", phy, output);
	parse_hw_capabilities(actor, output);

	string mac = exec("cat /sys/class/ieee80211/" + phy + "/macaddress 2>/dev/null");
	while(!mac.empty() && (mac.back() == '\n' || mac.back() == '\r')) mac.pop_back();
	if(!mac.empty()){
		actor->set(SK::mac, mac);
		actor->set(SK::permanent_mac, mac);
	}

	const string driver = get_driver(actor.get(SK::radio));
	if(!driver.empty()){
		actor->set(SK::driver_name, driver);
		actor->set(SK::driver_hash, get_driver_hash(driver));
		actor->set(SK::module_hash, get_module_hash(driver));
	}
}

void OpenWrtConn::parse_hw_capabilities(const ActorPtr &actor, const string &output){
	auto has = [&](const string &tag){ return output.find(tag) != string::npos; };

	actor->set(BK::GHz2_4, has("Band 1:"));
	actor->set(BK::GHz5, has("Band 2:"));
	actor->set(BK::GHz6, has("* 6.0 GHz") || has("Band 3:"));

	actor->set(BK::AP, has(" * AP"));
	actor->set(BK::STA, has(" * managed"));
	actor->set(BK::monitor, has(" * monitor"));
	actor->set(BK::active_monitor, has("active monitor"));

	actor->set(BK::w80211n, has("HT20") || has("HT40"));
	actor->set(BK::w80211ac, has("VHT"));
	actor->set(BK::w80211ax, has("HE"));

	actor->set(BK::CSA,         has("channel_switch"));
	actor->set(BK::OCV,         has("operating channel validation"));
	actor->set(BK::beacon_prot, has("beacon protection"));
	actor->set(BK::MFP,         has("00-0f-ac:6")); // BIP-CMAC-128

	actor->set(BK::WPA_PSK,  has("00-0f-ac:4")); // CCMP cipher suite
	actor->set(BK::WPA3_SAE, has("SAE"));
}
}