#include "ex_program/external_actors/openwrt/OpenWrtConn.h"

#include "config/global_config.h"
#include "logger/error_log.h"
#include "observer/observers.h"
#include "system/ip.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester {
    using namespace std;

    void OpenWrtConn::check_req(const nlohmann::json &config, const std::string &actor_name){
        //TODO check config
        //exec("opkg update");
        const auto& setup_node = config.at("actors").at(actor_name).at("setup");
        if(!setup_node.contains("req_programs")){return;}
        auto req_programs = setup_node.at("req_programs");
        for (const auto& program_name : req_programs) {
            int ret = 0;
            exec("opkg install "+program_name.get<string>(), false, &ret);
            if(ret){throw config_err("Cannot install "+program_name.get<string>()+", try opkg update");}
        }
    }

    //FIXME hnusné čekání, podívat se na inotifywait
    string OpenWrtConn::wait_for_ifname(const string& section) const {
        constexpr int retries = 10;
        for (int i = 0; i < retries; i++) {
            const auto j = nlohmann::json::parse(exec("wifi status 2>/dev/null"));
            for (const auto& [radio_name, radio] : j.items()) {
                for (const auto& iface : radio.at("interfaces")) {
                    if (iface.value("section", "") == section && iface.contains("ifname"))
                        return iface["ifname"].get<string>();
                }
            }
            log(LogLevel::DEBUG, "Waiting for ifname of %s (%d/%d)", section.c_str(), i+1, retries);
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        throw ex_conn_err("ifname not available for section: "+section);
    }

    void OpenWrtConn::forward_internet(const string& remote_ip) const{
        hw_capabilities::run_cmd({"bash", "-c", "echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward"});
        auto  internet_iface = get_global_config().at("internet_interface").get<string>();
        hw_capabilities::run_cmd({"sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", internet_iface, "-j", "MASQUERADE"});
        const string local_iface = hw_capabilities::get_iface(remote_ip);
        const string local_ip = ip::get_ip(local_iface);

        exec("uci set network.lan.gateway="+local_ip);
        exec("uci set network.lan.dns=8.8.8.8");
        exec("uci commit network");
        exec("/etc/init.d/network restart");
    }

    void OpenWrtConn::time_fix() const{
        exec("/etc/init.d/sysntpd stop");
        int ret = 0;
        exec("ntpd -q -n -p 0.openwrt.pool.ntp.org", false, &ret);
        if (ret != 0) throw ex_conn_err("Failed to sync time with NTP");
        exec("/etc/init.d/sysntpd start");
    }

    void OpenWrtConn::setup_iface(const std::string &radio_name, const std::shared_ptr<Actor_config> &actor) {
        const auto j = nlohmann::json::parse(exec("wifi status 2>/dev/null"));

        if (!j.contains(radio_name)) throw ex_conn_err("Radio not found: "+radio_name);
        const auto& radio = j.at(radio_name);

        // enable disabled radio
        if (radio.value("disabled", false)) exec("uci set wireless."+radio_name+".disabled=0");

        // find existing section or create new
        string section;
        for (const auto& iface : radio.at("interfaces")) {
            if (iface.contains("section")) {
                section = iface.at("section").get<string>();
                break;  // reuse existing
            }
        }
        if (section.empty()) section = "wpa3_tester_"+radio_name;  // create new

        log(LogLevel::DEBUG, "Setting up wifi-iface "+section+" for "+radio_name);

        exec("uci set wireless."+section+"=wifi-iface");
        exec("uci set wireless."+section+".device="+radio_name);
        exec("uci set wireless."+section+".mode="+actor->str_con["mode"].value_or("ap"));
        exec("uci set wireless."+section+".ssid="+actor->str_con["ssid"].value_or("OpenWrt_"+radio_name));
        exec("uci set wireless."+section +".encryption="+actor->str_con["encryption"].value_or("none"));
        exec("uci set wireless."+section +".network=lan");

        if (actor->str_con["key"].has_value())
            exec("uci set wireless."+section +".key="+actor->str_con["key"].value());

        exec("uci commit wireless");
        exec("wifi reload");

        // wait for ifname and store in actor
        actor->str_con["iface"] = wait_for_ifname(section);
        actor->str_con["mac"] = get_mac_address(actor->str_con["iface"].value());
        actor->str_con["radio"] = radio_name;
    }

    bool OpenWrtConn::connect(const ActorPtr &actor) {
        const bool success = ExternalConn::connect(actor);
        if (success) {
            forward_internet(actor["whitebox_ip"]);
            time_fix();
        }
        return success;
    }

    vector<string> OpenWrtConn::get_radio_list() {
        const string output = exec("wifi status 2>/dev/null");
        const auto j = nlohmann::json::parse(output);
        vector<string> radios;
        for (const auto& [radio_name, radio] : j.items()) {
            radios.push_back(radio_name);
        }
        return radios;
    }

    void OpenWrtConn::set_monitor_mode(const std::string &iface) const{
        exec("wifi down");  // stop hostapd/supplicant
        ExternalConn::set_monitor_mode(iface);
    }

    void OpenWrtConn::set_managed_mode(const std::string &iface) const{
        ExternalConn::set_managed_mode(iface);
        exec("wifi up");  // restart hostapd/supplicant
    }

    auto OpenWrtConn::set_ip(const std::string &iface, const std::string &ip_addr) const -> void {
        const auto j = nlohmann::json::parse(exec("wifi status 2>/dev/null"));

        string iface_safe = iface;
        ranges::replace(iface_safe, '-', '_');
        const string wpa3_section = "wpa3_tester_"+iface_safe;

        int rc;
        exec("uci get network."+wpa3_section +" 2>/dev/null", false, &rc);
        if (rc != 0) {
            exec("uci set network."+wpa3_section +"=interface");
            exec("uci set network."+wpa3_section +".proto=static");

            for (const auto& [radio_name, radio] : j.items()) {
                for (const auto& wifi_iface : radio.at("interfaces")) {
                    if (wifi_iface.value("ifname", "") == iface) {
                        const string wifi_section = wifi_iface.at("section").get<string>();
                        exec(format("uci set wireless.{}.network={}", wifi_section, wpa3_section));
                    }
                }
            }
            exec("uci commit wireless");
        }

        exec("uci set network."+wpa3_section +".ipaddr="+ip_addr);
        exec("uci set network."+wpa3_section +".netmask=255.255.255.0");
        exec("uci commit network");
        exec("/etc/init.d/network restart");
    }

    string OpenWrtConn::get_radio(const string &iface) const{
        return exec("uci show wireless | grep "+iface +" | cut -d. -f2");
    }

    string OpenWrtConn::get_wifi_iface_section(const string& iface) const {
        const auto j = nlohmann::json::parse(exec("wifi status 2>/dev/null"));

        for (const auto& [radio_name, radio] : j.items()) {
            for (const auto& wifi_iface : radio.at("interfaces")) {
                if (wifi_iface.value("ifname", "") == iface)
                    return wifi_iface.at("section").get<string>();
                const string sec = wifi_iface.value("section", "");
                if (!sec.empty()) {
                    const string uci_iface = exec("uci get wireless."+sec +".ifname 2>/dev/null");
                    if (uci_iface.find(iface) != string::npos)
                        return sec;
                }
            }
        }
        throw ex_conn_err("No section found for iface: "+iface);
    }

    // -------------------------------------------

    string OpenWrtConn::get_wifi_iface_index(const string& radio) const{
        const string output = exec("uci show wireless | grep '\\.device=' | grep -n '="+radio + "' | cut -d: -f1");
        if (output.empty()) return "0"; //FIXME quite fallback
        const int line = stoi(output) - 1; // uci index from 0
        return to_string(line);
    }

    void OpenWrtConn::setup_ap(const RunStatus& rs, const ActorPtr &actor) {
        nlohmann::json program_config = rs.config.at("actors").at(actor["actor_name"]).at("setup").at("program_config");

        // radio level keys
        static const set<string> radio_keys = {"channel", "htmode", "txpower", "country", "beacon_int", "noscan", "disabled"};
        const string wifi_iface = get_wifi_iface_section(actor["iface"]);

        exec("uci set wireless."+actor["radio"] + ".disabled=0");
        exec("uci set wireless."+wifi_iface + ".device="+actor["radio"]);
        for (const auto& [key, val] : program_config.items()) {
            const string value = val.is_string() ? val.get<string>() : val.dump();

            if (radio_keys.contains(key)){
                exec(format("uci set wireless.{}.{}={}", actor["radio"], key, value));
            }else{
                exec(format("uci set wireless.{}.{}={}", wifi_iface, key, value));
            }
        }
        exec("uci commit wireless");
        exec("wifi reload");
    }

    void OpenWrtConn::logger(RunStatus& rs, const std::string &actor_name){
        const auto actor = rs.get_actor(actor_name);
        const string host = actor["whitebox_ip"];
        const string user = actor["ssh_user"];
        const vector<string> command = {
            "stdbuf", "-oL",  // Line buffering for stdout
            "sshpass", "-p", actor["ssh_password"],
            "ssh", "-o", "StrictHostKeyChecking=no",
            user + "@"+host,
            "logread -f"
        };
        rs.process_manager.run(actor_name , command);
    }

    void OpenWrtConn::get_hw_capabilities(Actor_config& cfg, const std::string& radio) {
        const string phy = "phy"+radio.substr(5);
        int ret = 0;
        const string output = exec("iw phy "+phy + " info", false, &ret);
        if (ret != 0) {throw ex_conn_err("Failed to get hw capabilities for phy "+phy + ": "+output);}
        parse_hw_capabilities(cfg, output);
    }

    void OpenWrtConn::parse_hw_capabilities(Actor_config& cfg, const std::string& output) {
        // supported bands
        cfg.bool_conditions["2_4GHz"] = (output.find("Band 1:") != string::npos);
        cfg.bool_conditions["5GHz"] = (output.find("Band 2:") != string::npos);
        cfg.bool_conditions["6GHz"] = (
            output.find("* 6.0 GHz") != string::npos || output.find("Band 3:") != string::npos
        );

        // supported modes
        cfg.bool_conditions["AP"] = (output.find(" * AP") != string::npos);
        cfg.bool_conditions["STA"] = (output.find(" * managed") != string::npos);
        cfg.bool_conditions["monitor"] = (output.find(" * monitor") != string::npos);

        // Supported standards
        cfg.bool_conditions["80211n"] = (output.find("HT20") != string::npos || output.find("HT40") != string::npos);
        cfg.bool_conditions["80211ac"] = (output.find("VHT") != string::npos);
        cfg.bool_conditions["80211ax"] = (output.find("HE") != string::npos);
    }
}
