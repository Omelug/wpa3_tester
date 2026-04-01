#include "attacks/mc_mitm/wifi_util.h"

#include <cstdio>
#include <fstream>
#include <regex>
#include <stdexcept>

#include <tins/tins.h>

#include "logger/log.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace Tins;

//TODO uklidit do hwcapabilities
void exec(const vector<string>& cmd, bool check) {
    string full;
    for (auto& s : cmd) full += s + " ";
    const int ret = system(full.c_str());
    if (check && ret != 0)
        throw runtime_error("Command failed: " + full);
}

string get_macaddress(const string& iface) {
    ifstream f("/sys/class/net/" + iface + "/address");
    string mac;
    getline(f, mac);
    return mac;
}

string get_iface_type(const string& iface) {
    const string out = wpa3_tester::hw_capabilities::run_cmd_output({"iw", iface, "info"});
    const regex re("type (\\w+)");
    smatch m;
    if (!regex_search(out, m, re)) return "";
    return m[1];
}

void set_ap_mode(const string& iface) {
    exec({"ifconfig", iface, "down"});
    if (get_iface_type(iface) != "AP")
        exec({"iw", iface, "set", "type", "__ap"});
    exec({"ifconfig", iface, "up"});
}

void start_ap(const string& iface, const int channel, Dot11Beacon* beacon) {
    string ssid;
    string head_hex, tail_hex;

    if (beacon) {
        const PDU::serialization_type raw = beacon->serialize();
        // For simplicity we pass the whole beacon as head (no tail split here)
        // A more complete impl would split at TIM; left as a TODO
        head_hex.reserve(raw.size() * 2);
        for (const uint8_t b : raw) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", b);
            head_hex += buf;
        }
        if (ssid.empty())
            ssid = get_ssid(*beacon);
    }

    if (ssid.empty())
        ssid = "libwifi-ap-" + get_macaddress(iface);

    vector<string> cmd = {
        "iw", "dev", iface, "ap", "start",
        ssid, to_string(wpa3_tester::hw_capabilities::channel_to_freq(channel)),
        "100", "1"  // beacon interval TU, DTIM period
    };
    if (!head_hex.empty())
        cmd.insert(cmd.end(), {"head", head_hex});

    set_ap_mode(iface);
    log(wpa3_tester::LogLevel::INFO, "Starting AP: " + [&]{ string s; for (auto& t:cmd) s+=t+" "; return s; }());
    exec(cmd);
    exec({"ifconfig", iface, "up"});
}

void stop_ap(const string& iface) {
    log(wpa3_tester::LogLevel::INFO, "Stopping AP on " + iface);
    exec({"iw", "dev", iface, "ap", "stop"});
}

bool dot11_is_group(const Dot11& pkt) {
    // Group-addressed = LSB of first byte of addr1 is set
    const auto& a = pkt.addr1();
    return (a[0] & 0x01) != 0;
}

string get_ssid(const Dot11Beacon& beacon) {
    const auto opt = beacon.search_option(Dot11::SSID);
    if (!opt) return "";
    return std::string(opt->data_ptr(), opt->data_ptr() + opt->data_size());
}

const Dot11::option* get_element(const Dot11& pkt, uint8_t id) {
    for (const auto& opt : pkt.options()) {
        if (opt.option() == id)
            return &opt;
    }
    return nullptr;
}

Dot11ProbeResponse* beacon_to_probe_resp(const Dot11Beacon& beacon) {
    auto* resp = new Dot11ProbeResponse();
    resp->addr2(beacon.addr2());
    resp->addr3(beacon.addr3());
    resp->timestamp(0xAAAAAAAAAAAAAAAAULL);
    resp->interval(beacon.interval());
    resp->capabilities() = beacon.capabilities();

    // Copy all IEs except TIM
    for (const auto& opt : beacon.options()) {
        if (opt.option() != IEEE_TLV_TYPE_TIM)
            resp->add_option(opt);
    }
    return resp;
}