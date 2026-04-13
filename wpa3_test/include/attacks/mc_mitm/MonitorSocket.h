#pragma once
#include <string>
#include <memory>

namespace wpa3_tester {

    class MonitorSocket{
    public:
        explicit MonitorSocket(const std::string& iface, bool detect_injected = false);

        void send(Tins::PDU &pdu, int channel);
        std::unique_ptr<Tins::PDU> recv();
        pcap_t* get_pcap_handle() { return sniffer_.get_pcap_handle(); }
        Tins::Sniffer& sniffer() { return sniffer_; }

        void set_filter(const std::string &bpf);
    private:
        static Tins::SnifferConfiguration make_sniff_cfg();
        static void strip_fcs(Tins::RadioTap& rt);
        std::string iface_;
        bool detect_injected_;
        Tins::PacketSender sender_;
        Tins::Sniffer sniffer_;
    };
}
