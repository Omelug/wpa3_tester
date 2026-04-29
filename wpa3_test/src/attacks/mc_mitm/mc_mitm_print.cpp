#include "attacks/mc_mitm/mc_mitm.h"

#include <utility>
#include <tins/tins.h>
#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;
using namespace chrono;
using namespace Tins;

static uint16_t get_seq_num(const Dot11 &pkt){
    if(const auto *mgmt = pkt.find_pdu<Dot11ManagementFrame>()) return mgmt->seq_num();
    if(const auto *data = pkt.find_pdu<Dot11Data>()) return data->seq_num();
    return 0;
}

string McMitm::frame_to_str(const Dot11 &pkt) {
    const auto type = pkt.type();
    const auto sub = pkt.subtype();

    static const unordered_map<int, string> mgmt_names = {
        {Dot11::BEACON, "Beacon"}, {Dot11::PROBE_REQ, "ProbeReq"},
        {Dot11::PROBE_RESP, "ProbeResp"}, {Dot11::AUTH, "Auth"},
        {Dot11::DEAUTH, "Deauth"}, {Dot11::ASSOC_REQ, "AssoReq"},
        {Dot11::REASSOC_REQ, "ReassoReq"}, {Dot11::ASSOC_RESP, "AssoResp"},
        {Dot11::REASSOC_RESP, "ReassoResp"}, {Dot11::DISASSOC, "Disas"},
        {13, "Action"},
    };
    static const unordered_map<int, string> ctrl_names = {
        {Dot11::BLOCK_ACK, "BlockAck"}, {Dot11::RTS, "RTS"}, {Dot11::ACK, "Ack"},
    };

    static const unordered_map<int, string> data_names = {
        {Dot11::DATA_DATA,        "Data"},
        {Dot11::DATA_NULL,        "Null"},
        {Dot11::QOS_DATA_DATA,    "QoS-Data"},
        {Dot11::QOS_DATA_NULL,    "QoS-Null"},
        {Dot11::CF_ACK,           "CF-Ack"},
        {Dot11::CF_POLL,          "CF-Poll"},
    };

    const auto *names = type == Dot11::MANAGEMENT ? &mgmt_names
                      : type == Dot11::CONTROL    ? &ctrl_names
                      : type == Dot11::DATA       ? &data_names
                      : nullptr;

    if(names) {
        if(const auto it = names->find(sub); it != names->end()) {
            auto s = it->second;
            if(type != Dot11::CONTROL)
                s += "(seq=" + to_string(get_seq_num(pkt)) + ")";
            return s;
        }
    }

    return "Frame(type=" + to_string(type) +
           ",sub=" + to_string(sub) + ")";
}

void McMitm::print_rx(const LogLevel level, const string &prefix,
                      const Dot11 &frame, const string &suffix
){
    if(frame.type() == Dot11::CONTROL) return;

    string addr2;
    if(const auto *mgmt = frame.find_pdu<Dot11ManagementFrame>()){
        addr2 = mgmt->addr2().to_string();
    } else if(const auto *data = frame.find_pdu<Dot11Data>()){
        addr2 = data->addr2().to_string();
    }else if(frame.type() == Dot11::MANAGEMENT){
        const auto raw = const_cast<Dot11&>(frame).serialize();
        if(raw.size() >= 16)
            addr2 = HWAddress<6>(raw.data() + 10).to_string();
    }

    string msg = prefix + ": " + addr2 + " -> " + frame.addr1().to_string() + ": " + frame_to_str(frame);

    if(!suffix.empty()) msg += suffix;
    log(level, msg);
}

void McMitm::display_client_traffic(
    const PDU &pdu,
    const std::string &prefix,
    const std::string &suffix
){
    const auto *dot11 = pdu.find_pdu<Dot11>();
    if(!dot11) return;

    const auto *data = pdu.find_pdu<Dot11Data>();
    const bool is_null = data && (data->subtype() == Dot11::DATA_NULL ||
                                   data->subtype() == Dot11::QOS_DATA_NULL);

    const auto level = is_eapol(pdu) || (dot11->type() == Dot11::DATA && !is_null)
                     ? LogLevel::INFO
                     : LogLevel::DEBUG;

    print_rx(level, prefix, *dot11, suffix);
}
}