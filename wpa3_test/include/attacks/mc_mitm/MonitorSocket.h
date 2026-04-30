#pragma once
#include <memory>
#include <string>

namespace wpa3_tester{
class MonitorSocket{
public:
    explicit MonitorSocket(const std::string &iface, bool detect_injected = false);

    struct RecvResult {
        std::unique_ptr<Tins::PDU> pdu;
        std::vector<uint8_t> raw;
        explicit operator bool() const { return pdu != nullptr || !raw.empty(); }
    };

    void send(Tins::PDU &pdu, int channel);
    static RecvResult parse_frame(const u_char *frame, uint32_t caplen);
    RecvResult recv();
    pcap_t *get_pcap_handle(){ return sniffer_.get_pcap_handle(); }
    Tins::Sniffer &sniffer(){ return sniffer_; }

    void set_filter(const std::string &bpf);
private:
    static Tins::SnifferConfiguration make_sniff_cfg();
    bool detect_injected_;
    Tins::PacketSender sender_;
    Tins::Sniffer sniffer_;
};
}