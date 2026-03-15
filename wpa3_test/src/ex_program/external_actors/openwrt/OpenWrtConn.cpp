#include "ex_program/external_actors/openwrt/OpenWrtConn.h"

#include "config/global_config.h"
#include "logger/error_log.h"
#include "system/ip.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester {
    using namespace std;

    void OpenWrtConn::forward_internet(const string& remote_ip) const{
        hw_capabilities::run_cmd({"bash", "-c", "echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward"});
        auto  internet_iface = get_global_config().at("internet_interface").get<string>();
        hw_capabilities::run_cmd({"sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", internet_iface, "-j", "MASQUERADE"});
        const string local_iface = hw_capabilities::get_iface(remote_ip);
        const string local_ip = ip::get_ip(local_iface);

        exec("uci set network.lan.gateway=" + local_ip);
        exec("uci set network.lan.dns=8.8.8.8"); //TODO najít lepší DNS
        exec("uci commit network");
        exec("/etc/init.d/network restart");
    }

    void OpenWrtConn::time_fix() const{
        exec("/etc/init.d/sysntpd stop");
        exec("ntpd -q -n -p 0.openwrt.pool.ntp.org");
        exec("/etc/init.d/sysntpd start");
    }

    void OpenWrtConn::check_req(const RunStatus& rs, const string& actor_name) const{
        //exec("opkg update");
        const auto& req_programs = rs.config.at("actors").
                at(actor_name).at("setup").at("program_config").at("req_programs");

        for (const auto& program_name : req_programs) {
            int ret;
            exec("opkg install " + program_name.get<string>(), &ret);
            if(ret){throw config_error("Connot install " + program_name.get<string>() + "try opkg update");}
        }
    }

    //FIXME hnusné čekání, podívat se na inotifywait
    string OpenWrtConn::wait_for_ifname(const string& section, const int retries) const {
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
        throw ex_conn_err("ifname not available for section: " + section);
    }


    void OpenWrtConn::setup_iface(const std::string &radio_name, const std::shared_ptr<Actor_config> &actor) {
        const auto j = nlohmann::json::parse(exec("wifi status 2>/dev/null"));

        if (!j.contains(radio_name)) throw ex_conn_err("Radio not found: " + radio_name);
        const auto& radio = j.at(radio_name);

        // enable disabled radio
        if (radio.value("disabled", false))
            exec("uci set wireless." + radio_name + ".disabled=0");

        // find existing section or create new
        string section;
        for (const auto& iface : radio.at("interfaces")) {
            if (iface.contains("section")) {
                section = iface.at("section").get<string>();
                break;  // reuse existing
            }
        }
        if (section.empty()) section = "wpa3_tester_" + radio_name;  // create new

        log(LogLevel::DEBUG, "Setting up wifi-iface %s for %s", section.c_str(), radio_name.c_str());

        exec("uci set wireless." + section + "=wifi-iface");
        exec("uci set wireless." + section + ".device=" + radio_name);
        exec("uci set wireless." + section + ".mode=" + actor->str_con["mode"].value_or("ap"));
        exec("uci set wireless." + section + ".ssid=" + actor->str_con["ssid"].value_or("OpenWrt_" + radio_name));
        exec("uci set wireless." + section + ".encryption=" + actor->str_con["encryption"].value_or("none"));
        exec("uci set wireless." + section + ".network=lan");

        if (actor->str_con["key"].has_value())
            exec("uci set wireless." + section + ".key=" + actor->str_con["key"].value());

        exec("uci commit wireless");
        exec("wifi reload");

        // wait for ifname and store in actor
        actor->str_con["iface"] = wait_for_ifname(section);
        actor->str_con["radio"] = radio_name;
    }

    bool OpenWrtConn::connect(const RunStatus& rs, const ActorPtr &actor) {
        const bool success = ExternalConn::connect(rs, actor);
        if (success) {
            forward_internet(actor["whitebox_ip"]);
            time_fix();
            check_req(rs, actor["actor_name"]);
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

        string section = get_wifi_iface_section(iface);

        log(LogLevel::DEBUG, "looking for iface: %s", iface.c_str());
        for (const auto& [radio_name, radio] : j.items()) {
            for (const auto& wifi_iface : radio.at("interfaces")) {
                log(LogLevel::DEBUG, "found ifname: %s section: %s",
                    wifi_iface.value("ifname", "").c_str(),
                    wifi_iface.value("section", "").c_str());
            }
        }
        exec("uci set network." + section + ".ipaddr=" + ip_addr);
        exec("uci set network." + section + ".netmask=255.255.255.0");
        exec("uci commit network");
        exec("/etc/init.d/network restart");
    }

    string OpenWrtConn::get_radio(const string &iface) const{
        return exec("uci show wireless | grep " + iface + " | cut -d. -f2");
    }

    string OpenWrtConn::get_wifi_iface_section(const string& iface) const {
        const auto j = nlohmann::json::parse(exec("wifi status 2>/dev/null"));

        for (const auto& [radio_name, radio] : j.items()) {
            for (const auto& wifi_iface : radio.at("interfaces")) {
                if (wifi_iface.value("ifname", "") == iface)
                    return wifi_iface.at("section").get<string>();
                const string sec = wifi_iface.value("section", "");
                if (!sec.empty()) {
                    const string uci_iface = exec("uci get wireless." + sec + ".ifname 2>/dev/null");
                    if (uci_iface.find(iface) != string::npos)
                        return sec;
                }
            }
        }
        throw ex_conn_err("No section found for iface: " + iface);
    }

    // -------------------------------------------

    string OpenWrtConn::get_wifi_iface_index(const string& radio) const{
        const string output = exec("uci show wireless | grep '\\.device=' | grep -n '=" + radio + "' | cut -d: -f1");
        if (output.empty()) return "0"; //FIXME quite fallback
        const int line = stoi(output) - 1; // uci index from 0
        return to_string(line);
    }

    void OpenWrtConn::setup_ap(const RunStatus& rs, const ActorPtr &actor) {
        nlohmann::json program_config = rs.config.at("actors").at(actor["actor_name"]).at("setup").at("program_config");
        const string radio = get_radio(actor["iface"]);

        // radio level keys
        static const set<string> radio_keys = {"channel", "htmode", "txpower", "country", "beacon_int", "noscan", "disabled"};
        const string wifi_iface = get_wifi_iface_section(actor["iface"]);

        exec("uci set wireless." + radio + ".disabled=0");
        exec("uci set wireless." + wifi_iface + ".device=" + radio);
        for (const auto& [key, val] : program_config.items()) {
            const string value = val.is_string() ? val.get<string>() : val.dump();

            if (radio_keys.contains(key)){
                exec("uci set wireless." + radio + "." + key + "=" + value);
            }else{
                exec("uci set wireless." + wifi_iface + "." + key + "=" + value);
            }
        }
        exec("uci commit wireless");
        exec("wifi reload");
    }
}

