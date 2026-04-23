#include "attacks/mc_mitm/mc_mitm.h"

#include <cstring>
#include <chrono>
#include <utility>
#include <tins/tins.h>
#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "attacks/mc_mitm/wifi_util.h"
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

string McMitm::frame_to_str(const Dot11 &pkt){
    ostringstream ss;

    if(pkt.type() == Dot11::MANAGEMENT){
        const auto sub = pkt.subtype();
        if(sub == Dot11::BEACON){
            ss << "Beacon(seq=" << get_seq_num(pkt) << ")";
            return ss.str();
        }
        if(sub == Dot11::PROBE_REQ){
            ss << "ProbeReq(seq=" << get_seq_num(pkt) << ")";
            return ss.str();
        }
        if(sub == Dot11::PROBE_RESP){
            ss << "ProbeResp(seq=" << get_seq_num(pkt) << ")";
            return ss.str();
        }
        if(sub == Dot11::AUTH){
            ss << "Auth(seq=" << get_seq_num(pkt) << ")";
            return ss.str();
        }
        if(sub == Dot11::DEAUTH){
            ss << "Deauth(seq=" << get_seq_num(pkt) << ")";
            return ss.str();
        }
        if(sub == Dot11::ASSOC_REQ){
            ss << "AssoReq(seq=" << get_seq_num(pkt) << ")";
            return ss.str();
        }
        if(sub == Dot11::REASSOC_REQ){
            ss << "ReassoReq(seq=" << get_seq_num(pkt) << ")";
            return ss.str();
        }
        if(sub == Dot11::ASSOC_RESP){
            ss << "AssoResp(seq=" << get_seq_num(pkt) << ")";
            return ss.str();
        }
        if(sub == Dot11::REASSOC_RESP){
            ss << "ReassoResp(seq=" << get_seq_num(pkt) << ")";
            return ss.str();
        }
        if(sub == Dot11::DISASSOC){
            ss << "Disas(seq=" << get_seq_num(pkt) << ")";
            return ss.str();
        }
        if(sub == 13){
            ss << "Action(seq=" << get_seq_num(pkt) << ")";
            return ss.str();
        }
    } else if(pkt.type() == Dot11::CONTROL){
        if(pkt.subtype() == Dot11::BLOCK_ACK) return "BlockAck";
        if(pkt.subtype() == Dot11::RTS) return "RTS";
        if(pkt.subtype() == Dot11::ACK) return "Ack";
    } else if(pkt.type() == Dot11::DATA){
        if(pkt.subtype() == Dot11::DATA_NULL){
            ss << "Null(seq=" << get_seq_num(pkt) << ")";
            return ss.str();
        }
        if(pkt.subtype() == Dot11::QOS_DATA_NULL){
            ss << "QoS-Null(seq=" << get_seq_num(pkt) << ")";
            return ss.str();
        }
    }

    ss << "Frame(type=" << static_cast<int>(pkt.type()) << ",sub=" << static_cast<int>(pkt.subtype()) << ")";
    return ss.str();
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
    }
    string msg = prefix + ": " + addr2 + " -> " + frame.addr1().to_string() + ": " + frame_to_str(frame);
    if(!suffix.empty()) msg += suffix;
    log(level, msg);
}

steady_clock::time_point McMitm::display_client_traffic(
    const PDU &pdu,
    const std::string &prefix,
    const steady_clock::time_point prevtime,
    const std::string &suffix
){
    const auto *dot11 = pdu.find_pdu<Dot11>();

    if(pdu.find_pdu<EAPOL>()){
        // EAPOL
        print_rx(LogLevel::INFO, prefix, *dot11, suffix);
    } else if(const auto *data = pdu.find_pdu<Dot11Data>(); // Data – Null / QoS Null
        data && (data->subtype() == Dot11::DATA_NULL ||
            data->subtype() == Dot11::QOS_DATA_NULL)){
        print_rx(LogLevel::DEBUG, prefix, *dot11, suffix);
    } else if(dot11 && dot11->type() == Dot11::DATA){
        print_rx(LogLevel::INFO, prefix, *dot11, suffix);
    } else if(dot11){
        print_rx(LogLevel::DEBUG, prefix, *dot11, suffix);
    }

    return prevtime;
}
}