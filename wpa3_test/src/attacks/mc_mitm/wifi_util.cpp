#include "attacks/mc_mitm/wifi_util.h"
#include <stdexcept>
#include "logger/log.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace Tins;

//TODO uklidit do hwcapabilities
void exec(const vector<string>& cmd, const bool check) {
    string full;
    for (auto& s : cmd) full += s + " ";
    const int ret = system(full.c_str());
    if (check && ret != 0)
        throw runtime_error("Command failed: " + full);
}


string get_ssid(const Dot11Beacon& beacon) {
    const auto opt = beacon.search_option(Dot11::SSID);
    if (!opt) return "";
    return string(opt->data_ptr(), opt->data_ptr() + opt->data_size());
}

Dot11ProbeResponse beacon_to_probe_resp(const Dot11Beacon &beacon, const int rogue_channel) {
    auto resp = Dot11ProbeResponse();
    resp.addr2(beacon.addr2());
    resp.addr3(beacon.addr3());
    resp.timestamp(0xAAAAAAAAAAAAAAAAULL);
    resp.interval(beacon.interval());
    resp.capabilities() = beacon.capabilities();

    for (const auto& opt : beacon.options()) {
        if (opt.option() == Dot11::TIM ) continue; // remove, not in probe responses
        if (opt.option() == Dot11::DS_SET) {
            uint8_t ch = rogue_channel;
            resp.add_option({Dot11::DS_SET, 1, &ch});
            continue;
        }
        //FIXME in python is HT_OPRAITon unchanged
        if (opt.option() == Dot11::HT_OPERATION && opt.data_size() >= 1) {
            vector ht_data(opt.data_ptr(), opt.data_ptr() + opt.data_size());
            ht_data[0] = rogue_channel;
            resp.add_option({Dot11::HT_OPERATION, ht_data.size(), ht_data.data()});
            continue;
        }
        resp.add_option(opt);
    }

    return resp;
}

//TODO move
Dot11Beacon* beacon_channel_patch(const Dot11Beacon& beacon, const int rogue_channel) {
    auto* resp = new Dot11Beacon();
    resp->addr1(Dot11::BROADCAST);
    resp->addr2(beacon.addr2());
    resp->addr3(beacon.addr3());
    //resp->timestamp(0xAAAAAAAAAAAAAAAAULL);
    resp->interval(beacon.interval());
    resp->capabilities() = beacon.capabilities();


    for (const auto& opt : beacon.options()) {
        if (opt.option() == Dot11::DS_SET) {
            uint8_t ch = rogue_channel;
            resp->add_option({Dot11::DS_SET, 1, &ch});
            continue;
        }
        if (opt.option() == Dot11::HT_OPERATION && opt.data_size() >= 1) {
            vector ht(opt.data_ptr(), opt.data_ptr() + opt.data_size());
            ht[0] = rogue_channel;
            resp->add_option({Dot11::HT_OPERATION, ht.size(), ht.data()});
            continue;
        }
        resp->add_option(opt);
    }
    return resp;
}

Dot11AssocResponse* assoc_resp_channel_patch(const Dot11AssocResponse& assoc, const int rogue_channel) {
    auto* resp = new Dot11AssocResponse();
    resp->addr1(assoc.addr1());
    resp->addr2(assoc.addr2());
    resp->addr3(assoc.addr3());
    resp->capabilities() = assoc.capabilities();
    resp->status_code(assoc.status_code());
    resp->aid(assoc.aid());
    resp->seq_num(assoc.seq_num());

    for (const auto& opt : assoc.options()) {
        if (opt.option() == Dot11::HT_OPERATION && opt.data_size() >= 1) {
            vector ht_data(opt.data_ptr(), opt.data_ptr() + opt.data_size());
            ht_data[0] = rogue_channel;
            resp->add_option({Dot11::HT_OPERATION, ht_data.size(), ht_data.data()});
            continue;
        }
        resp->add_option(opt);
    }

    return resp;
}

int get_eapol_msg_num(const RSNEAPOL* rsneapol) {
    if (!rsneapol) return 0;
    const uint8_t key_ack = rsneapol->key_ack();
    const uint8_t key_mic = rsneapol->key_mic();
    const uint8_t install = rsneapol->install();
    const uint8_t secure = rsneapol->secure();

    if (key_mic && !key_ack && !install && !secure) return 2; // M2
    if (key_mic && key_ack && install && secure) return 3;    // M3
    if (key_mic && !key_ack && !install && secure) return 4;  // M4
    if (!key_mic && key_ack && !install && !secure) return 1; // M1

    return 0;
}

Dot11ManagementFrame::channel_switch_type construct_csa(const uint8_t new_channel, const uint8_t count = 1){
    return Dot11ManagementFrame::channel_switch_type(
        1, //type
        new_channel,
        count);
}

Dot11Beacon append_csa(const Dot11Beacon& beacon, const uint8_t channel, const uint8_t count){
    Dot11Beacon copy = beacon;
    copy.channel_switch(construct_csa(channel, count));
    return copy;
}

void start_ap(const string& iface, const string& base_iface, int channel,
              const optional<Dot11Beacon>& beacon,
              const optional<string>& ssid,
              int interval, int dtim_period){
    Dot11Beacon bcn;

    // Use minimal beacon if not given, otherwise copy so the original isn't modified
    if (!beacon.has_value()) {
        const string own_mac = wpa3_tester::hw_capabilities::get_macaddress(iface);
        bcn.addr2(Tins::HWAddress<6>(own_mac));
        bcn.addr3(Tins::HWAddress<6>(own_mac));
    } else {
        bcn = *beacon;
    }

    // In order of priority: provided ssid, ssid from beacon, or default
    string ap_ssid;
    if (ssid.has_value()) {
        ap_ssid = *ssid;
    } else {
        const auto* ssid_ie = bcn.search_option(Dot11ManagementFrame::SSID);
        if (ssid_ie && ssid_ie->data_size() > 0)
            ap_ssid = string(reinterpret_cast<const char*>(ssid_ie->data_ptr()), ssid_ie->data_size());
        else
            ap_ssid = "libwifi-ap-" + wpa3_tester::hw_capabilities::get_macaddress(iface);
    }

    // Split beacon into head (before TIM) and tail (after TIM)
    Dot11Beacon head;
    head.addr1(bcn.addr1());
    head.addr2(bcn.addr2());
    head.addr3(bcn.addr3());
    head.interval(bcn.interval());
    head.capabilities() =bcn.capabilities();

    vector<uint8_t> tail_bytes;
    bool past_tim = false;

    for (const auto& opt : bcn.options()) {
        if (opt.option() == Dot11ManagementFrame::TIM) {
            past_tim = true;
            continue;
        }
        if (!past_tim) {
            head.add_option(opt);
        } else {
            // Serialize tail IEs manually
            tail_bytes.push_back(opt.option());
            tail_bytes.push_back(static_cast<uint8_t>(opt.data_size()));
            tail_bytes.insert(tail_bytes.end(), opt.data_ptr(), opt.data_ptr() + opt.data_size());
        }
    }

    // Serialize head to hex
    const auto head_bytes = head.serialize();
    ostringstream head_hex;
    for (const auto b : head_bytes)
        head_hex << hex << setw(2) << setfill('0') << static_cast<int>(b);

    const int freq = wpa3_tester::hw_capabilities::channel_to_freq(channel);

    vector<string> cmd = {
        "iw", "dev", iface, "ap", "start",
        ap_ssid,
        to_string(freq),
        to_string(interval),
        to_string(dtim_period),
        "head", head_hex.str()
    };

    if (!tail_bytes.empty()) {
        ostringstream tail_hex;
        for (const auto b : tail_bytes)
            tail_hex << hex << setw(2) << setfill('0') << static_cast<int>(b);
        cmd.emplace_back("tail");
        cmd.push_back(tail_hex.str());
    }

    wpa3_tester::hw_capabilities::run_cmd({"ifconfig", iface, "down"});
    //TODO some drivers drop kernel if up during subiface cchange to __ap ?  - maybe only ath_htc/mt7 ?
    //(weird af but I will not debug it if I need restart notebook for run)
    wpa3_tester::hw_capabilities::run_cmd({"ifconfig", base_iface, "down"});
    exec({"iw", iface, "set", "type", "__ap"});

    wpa3_tester::hw_capabilities::run_cmd({"iw", "dev", iface, "set", "channel", to_string(channel)});
    wpa3_tester::hw_capabilities::run_cmd({"iw", "dev", base_iface, "set", "channel", to_string(channel)});

    wpa3_tester::hw_capabilities::run_cmd({"ifconfig", base_iface, "up"});
    wpa3_tester::hw_capabilities::run_cmd({"ifconfig", iface, "up"});

    string cmd_str;
    for (const auto& arg : cmd) cmd_str += arg + " ";
    log(wpa3_tester::LogLevel::INFO, "Starting AP using: " + cmd_str);

    wpa3_tester::hw_capabilities::run_cmd(cmd);

    wpa3_tester::hw_capabilities::run_cmd({"iw", "dev", iface, "set", "channel", to_string(channel)});
    wpa3_tester::hw_capabilities::run_cmd({"iw", "dev", base_iface, "set", "channel", to_string(channel)});

    // With rt2800usb we need "ifconfig up" after "ap start" to make the interface
    // acknowledge received frames and send ACKs
    wpa3_tester::hw_capabilities::run_cmd({"ifconfig", base_iface, "up"});
    wpa3_tester::hw_capabilities::run_cmd({"ifconfig", iface, "up"});

}

void stop_ap(const string& iface){
    const vector<string> cmd = {"iw", "dev", iface, "ap", "stop"};
    log(wpa3_tester::LogLevel::INFO, "Stopping AP using: iw dev " + iface + " ap stop");
    wpa3_tester::hw_capabilities::run_cmd(cmd);
}

