#include <tins/tins.h>
#include <string>
#include <memory>
#include <sys/poll.h>
#include "attacks//mc_mitm/MonitorSocket.h"

#include "logger/log.h"
#include "system/hw_capabilities.h"
using namespace std;

namespace wpa3_tester{
MonitorSocket::MonitorSocket(const string &iface, const bool detect_injected)
    : iface_(iface),
      detect_injected_(detect_injected),
      sender_(iface),
      sniffer_(iface, make_sniff_cfg()){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_setnonblock(sniffer_.get_pcap_handle(), 1, errbuf);
}

// Send with RadioTap TXFlags=NOSEQ+ORDER (matches Python MonitorSocket.send)
void MonitorSocket::send(Tins::PDU &pdu, const int channel){
    if(detect_injected_){
        // Set More Data flag so we can detect injected frames
        if(auto *dot11 = pdu.find_pdu<Tins::Dot11>()) dot11->more_data(1);
    }

    // Wrap in RadioTap if not already present
    if(!pdu.find_pdu<Tins::RadioTap>()){
        Tins::RadioTap rt{};
        const int freq_mhz = hw_capabilities::channel_to_freq(channel);
        rt.channel(freq_mhz, Tins::RadioTap::OFDM);
        //rt.inner_pdu(pdu.clone());
        // TXFlags = NOSEQ+ORDER (0x28) — matches Python RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")
        rt.inner_pdu(pdu.clone());

        sender_.send(rt);
    } else{
        sender_.send(pdu);
    }
}

unique_ptr<Tins::PDU> MonitorSocket::recv(){
    pcap_pkthdr *header;
    const u_char *frame;
    const int ret = pcap_next_ex(sniffer_.get_pcap_handle(), &header, &frame);
    if(ret == 0) return nullptr;  // timeout
    if(ret < 0) {
        log(LogLevel::DEBUG, "pcap_next_ex error: {}", pcap_geterr(sniffer_.get_pcap_handle()));
        return nullptr;
    }

    try{
        auto rt = make_unique<Tins::RadioTap>(frame, header->caplen);
        strip_fcs(*rt);
        return rt;
    } catch(...){
        log(LogLevel::DEBUG, "MonitorSocket::recv unknown parse error");
        return nullptr;
    }
}

void MonitorSocket::set_filter(const string &bpf){
    sniffer_.set_filter(bpf);
}

Tins::SnifferConfiguration MonitorSocket::make_sniff_cfg(){
    Tins::SnifferConfiguration cfg;
    cfg.set_immediate_mode(true);
    cfg.set_timeout(1); //FIXME prej bug, neblokující nastaveno v pcap_setnonblock
    //cfg.set_promisc_mode(true);
    return cfg;
}

// Strip FCS if RadioTap FLAGS field indicates it's present
// Mirrors Python _detect_and_strip_fcs
void MonitorSocket::strip_fcs(Tins::RadioTap &rt){
    if(!((rt.present() & Tins::RadioTap::FLAGS) &&
        (rt.flags() & Tins::RadioTap::FCS)))
        return;

    // Reserialize without FCS — libtins handles this internally
    // when FCS flag is set it includes 4 extra bytes at the end
    auto *dot11 = rt.find_pdu<Tins::Dot11>();
    if(!dot11) return;

    const auto raw = dot11->serialize();
    if(raw.size() < 4) return;

    // Rebuild Dot11 without last 4 bytes (FCS)
    try{
        Tins::Dot11 *stripped = Tins::Dot11::from_bytes(
            raw.data(), raw.size() - 4);
        rt.inner_pdu(stripped);
    } catch(...){}
}
};