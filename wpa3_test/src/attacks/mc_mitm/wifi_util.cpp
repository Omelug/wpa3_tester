#include "attacks/mc_mitm/wifi_util.h"
#include <stdexcept>
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "system/netlink_guards.h"
#include "system/netlink_helper.h"

using namespace std;
using namespace Tins;

string get_ssid(const Dot11Beacon &beacon){
    const auto opt = beacon.search_option(Dot11::SSID);
    if(!opt) return "";
    return string(opt->data_ptr(), opt->data_ptr() + opt->data_size());
}

Dot11ProbeResponse beacon_to_probe_resp(const Dot11Beacon &beacon, const int rogue_channel){
    auto resp = Dot11ProbeResponse();
    resp.addr2(beacon.addr2());
    resp.addr3(beacon.addr3());
    resp.timestamp(0xAAAAAAAAAAAAAAAAULL);
    resp.interval(beacon.interval());
    resp.capabilities() = beacon.capabilities();

    for(const auto &opt: beacon.options()){
        if(opt.option() == Dot11::TIM) continue; // remove, not in probe responses
        if(opt.option() == Dot11::DS_SET){
            uint8_t ch = rogue_channel;
            resp.add_option({Dot11::DS_SET, 1, &ch});
            continue;
        }
        //FIXME in python is HT_OPRAITon unchanged
        if(opt.option() == Dot11::HT_OPERATION && opt.data_size() >= 1){
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
Dot11Beacon *beacon_channel_patch(const Dot11Beacon &beacon, const int rogue_channel){
    auto *resp = new Dot11Beacon();
    resp->addr1(Dot11::BROADCAST);
    resp->addr2(beacon.addr2());
    resp->addr3(beacon.addr3());
    //resp->timestamp(0xAAAAAAAAAAAAAAAAULL);
    resp->interval(beacon.interval());
    resp->capabilities() = beacon.capabilities();

    for(const auto &opt: beacon.options()){
        if(opt.option() == Dot11::DS_SET){
            uint8_t ch = rogue_channel;
            resp->add_option({Dot11::DS_SET, 1, &ch});
            continue;
        }
        if(opt.option() == Dot11::HT_OPERATION && opt.data_size() >= 1){
            vector ht(opt.data_ptr(), opt.data_ptr() + opt.data_size());
            ht[0] = rogue_channel;
            resp->add_option({Dot11::HT_OPERATION, ht.size(), ht.data()});
            continue;
        }
        resp->add_option(opt);
    }
    return resp;
}

Dot11AssocResponse *assoc_resp_channel_patch(const Dot11AssocResponse &assoc, const int rogue_channel){
    auto *resp = new Dot11AssocResponse();
    resp->addr1(assoc.addr1());
    resp->addr2(assoc.addr2());
    resp->addr3(assoc.addr3());
    resp->capabilities() = assoc.capabilities();
    resp->status_code(assoc.status_code());
    resp->aid(assoc.aid());
    resp->seq_num(assoc.seq_num());

    for(const auto &opt: assoc.options()){
        if(opt.option() == Dot11::HT_OPERATION && opt.data_size() >= 1){
            vector ht_data(opt.data_ptr(), opt.data_ptr() + opt.data_size());
            ht_data[0] = rogue_channel;
            resp->add_option({Dot11::HT_OPERATION, ht_data.size(), ht_data.data()});
            continue;
        }
        resp->add_option(opt);
    }

    return resp;
}

int get_eapol_msg_num(const PDU& pdu) {
    const auto* rsneapol = pdu.find_pdu<RSNEAPOL>();
    if (!rsneapol) return -1;
    const uint8_t key_ack = rsneapol->key_ack();
    const uint8_t key_mic = rsneapol->key_mic();
    const uint8_t install = rsneapol->install();
    const uint8_t secure = rsneapol->secure();

    if(key_mic && !key_ack && !install && !secure) return 2; // M2
    if(key_mic && key_ack && install && secure) return 3;    // M3
    if(key_mic && !key_ack && !install && secure) return 4;  // M4
    if(!key_mic && key_ack && !install && !secure) return 1; // M1

    return -1;
}

Dot11ManagementFrame::channel_switch_type construct_csa(const uint8_t new_channel, const uint8_t count = 1){
    return {
        1, //type
        new_channel,
        count
    };
}

Dot11Beacon append_csa(const Dot11Beacon &beacon, const uint8_t channel, const uint8_t count){
    Dot11Beacon copy = beacon;
    copy.channel_switch(construct_csa(channel, count));
    return copy;
}

static void check(wpa3_tester::netlink_helper::Result res, const string_view context){
    if(!res) throw system_error(res.error(), string{context});
}

bool power_mgmt(const Dot11 &dot11){
    if(const auto *mgmt = dot11.find_pdu<Dot11ManagementFrame>()) return mgmt->power_mgmt();
    if(const auto *data = dot11.find_pdu<Dot11Data>()) return data->power_mgmt();
    return false;
}

void start_ap(wpa3_tester::RunStatus &rs, const string &ap_iface, const wpa3_tester::ActorPtr &base_actor,
              int channel,
              const Dot11Beacon &beacon,
              optional<string> mac,
              int interval, int dtim_period
){
    // In order of priority: provided ssid, ssid from beacon, or default
    const auto *ssid_ie = beacon.search_option(Dot11ManagementFrame::SSID);
    if(!ssid_ie || ssid_ie->data_size() <= 0) throw runtime_error("invalid beacon for start ap");
    auto ap_ssid = string(reinterpret_cast<const char *>(ssid_ie->data_ptr()), ssid_ie->data_size());
    optional<string> netns = base_actor->str_con.at("netns");
    // Split beacon into head (before TIM) and tail (after TIM)

    Dot11Beacon head;
    head.addr1(beacon.addr1());
    head.addr2(beacon.addr2());
    head.addr3(beacon.addr3());
    head.interval(beacon.interval());
    head.capabilities() = beacon.capabilities();
    vector<uint8_t> tail_bytes;
    bool past_tim = false;

    for(const auto &opt: beacon.options()){
        if(opt.option() == Dot11ManagementFrame::TIM){
            past_tim = true;
            continue;
        }
        if(!past_tim){
            head.add_option(opt);
        } else{
            // Serialize tail IEs manually
            tail_bytes.push_back(opt.option());
            tail_bytes.push_back(static_cast<uint8_t>(opt.data_size()));
            tail_bytes.insert(tail_bytes.end(), opt.data_ptr(), opt.data_ptr() + opt.data_size());
        }
    }

    // Serialize head to hex
    const auto head_bytes = head.serialize();
    ostringstream head_hex;
    for(const auto b: head_bytes) head_hex << hex << setw(2) << setfill('0') << static_cast<int>(b);

    //TODO some drivers drop kernel if  const optional<string>& ssid = nullopt, up during subiface cchange to __ap ?  - maybe only ath_htc/mt7 ?
    //(weird af but I will not debug it if I need restart notebook for run)

    wpa3_tester::netlink_helper::NetlinkRegistry::get_fd(netns);
    base_actor->set_iface_down();
    wpa3_tester::hw_capabilities::run_cmd({"iw", "dev", ap_iface, "del"}, netns, false);
    check(wpa3_tester::netlink_helper::wait_for_iface_disappear(ap_iface, netns),
          format("'{}' did not disappear", ap_iface));

    base_actor->set_wifi_type(NL80211_IFTYPE_MONITOR);

    // ── step 2: add AP virtual interface ─────────────────────────────────────
    wpa3_tester::hw_capabilities::run_cmd({"iw", "dev", base_actor["iface"], "interface", "add", ap_iface, "type", "managed"}, netns);
    check(wpa3_tester::netlink_helper::wait_for_iface_appear(ap_iface, netns),
          format("'{}' did not appear", ap_iface));
    this_thread::sleep_for(2000ms); //FIXME tohele je hnusn=e, ale asi to funguje aspo+n nějak stabilně
    wpa3_tester::hw_capabilities::set_iface_down(ap_iface, netns);
    if(mac.has_value()) wpa3_tester::hw_capabilities::set_mac_address(ap_iface, mac.value(), netns);
    wpa3_tester::hw_capabilities::set_wifi_type(ap_iface, NL80211_IFTYPE_AP, netns);
    wpa3_tester::hw_capabilities::set_iface_up(ap_iface, netns);
    base_actor->set_iface_up();

    // start ap command
    vector<string> cmd = {
        "iw", "dev", ap_iface, "ap", "start",
        ap_ssid,
        to_string(wpa3_tester::hw_capabilities::channel_to_freq(channel)),
        to_string(interval),
        to_string(dtim_period),
        "head", head_hex.str()
    };

    if(!tail_bytes.empty()){
        ostringstream tail_hex;
        for(const auto b: tail_bytes) tail_hex << hex << setw(2) << setfill('0') << static_cast<int>(b);
        cmd.emplace_back("tail");
        cmd.push_back(tail_hex.str());
    }

    this_thread::sleep_for(chrono::milliseconds(200)); // firmware need som e time to up ?
    rs.process_manager.run(ap_iface + "_fake", cmd);

    // With rt2800usb we need "ifconfig up" after "ap start" to make the interface //TODO přepsáno z pythonu, zykoušet
    // acknowledge received frames and send ACKs
    //this_thread::sleep_for(chrono::milliseconds(100));
    base_actor->set_iface_up();
    wpa3_tester::hw_capabilities::set_iface_up(ap_iface, netns);
    //wpa3_tester::hw_capabilities::run_cmd({"iw", "dev", ap_iface, "set", "power_save", "off"}, netns);
}

void stop_ap(const string &iface, const optional<string> &netns){
    const vector<string> cmd = {"iw", "dev", iface, "ap", "stop"};
    log(wpa3_tester::LogLevel::INFO, "Stopping AP using: iw dev " + iface + " ap stop");
    wpa3_tester::hw_capabilities::run_cmd(cmd, netns);
}
