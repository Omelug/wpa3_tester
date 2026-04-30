#include "attacks//mc_mitm/MonitorSocket.h"
#include <memory>
#include <string>
#include <tins/tins.h>
#include "system/hw_capabilities.h"

using namespace std;
using namespace Tins;

namespace wpa3_tester{
MonitorSocket::MonitorSocket(const string &iface, const bool detect_injected)
    : detect_injected_(detect_injected),
      sender_(iface),
      sniffer_(iface, make_sniff_cfg()){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_setnonblock(sniffer_.get_pcap_handle(), 1, errbuf);
    if(pcap_setnonblock(sniffer_.get_pcap_handle(), 1, errbuf) == -1)
        throw runtime_error("pcap_setnonblock failed: " + string(errbuf));
}

// Send with RadioTap TXFlags=NOSEQ+ORDER (matches Python MonitorSocket.send)
void MonitorSocket::send(PDU &pdu, const int channel){
    if(detect_injected_){
        // Set More Data flag so we can detect injected frames
        if(auto *dot11 = pdu.find_pdu<Dot11>()) dot11->more_data(1);
    }

    // Wrap in RadioTap if not already present
    if(!pdu.find_pdu<RadioTap>()){
        RadioTap rt{};
        const int freq_mhz = hw_capabilities::channel_to_freq(channel);
        rt.channel(freq_mhz, RadioTap::OFDM);
        //rt.inner_pdu(pdu.clone());
        // TXFlags = NOSEQ+ORDER (0x28) — matches Python RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")
        rt.inner_pdu(pdu.clone());
        sender_.send(rt);
    } else{
        sender_.send(pdu);
    }
}

MonitorSocket::RecvResult MonitorSocket::parse_frame(const u_char *frame, uint32_t caplen) {
    try {
        const RadioTap rt(frame, caplen);
        uint32_t strip = 0;
        if (rt.present() & RadioTap::FLAGS && (rt.flags() & RadioTap::FCS))
            strip = 4;
        auto pdu = make_unique<RadioTap>(frame, caplen - strip);
        return { std::move(pdu), vector(frame, frame + caplen - strip) };
    } catch (...) {
        return {};
    }
}

MonitorSocket::RecvResult MonitorSocket::recv() {
    pcap_pkthdr *header;
    const u_char *frame;
    const int ret = pcap_next_ex(sniffer_.get_pcap_handle(), &header, &frame);
    if (ret <= 0) return {};
    return parse_frame(frame, header->caplen);
}

void MonitorSocket::set_filter(const string &bpf){ sniffer_.set_filter(bpf);}

SnifferConfiguration MonitorSocket::make_sniff_cfg(){
    SnifferConfiguration cfg;
    cfg.set_immediate_mode(true);
    cfg.set_timeout(1); //FIXME prej bug, neblokující nastaveno v pcap_setnonblock
    //cfg.set_promisc_mode(true);
    return cfg;
}
}