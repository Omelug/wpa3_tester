#include <tins/tins.h>
#include <string>
#include <memory>
#include <sys/poll.h>
#include "attacks//mc_mitm/MonitorSocket.h"

#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester {

    MonitorSocket::MonitorSocket(const std::string& iface, const bool detect_injected)
        : iface_(iface), detect_injected_(detect_injected),
          sender_(iface), sniffer_(iface, make_sniff_cfg())
    {}

    // Send with RadioTap TXFlags=NOSEQ+ORDER (matches Python MonitorSocket.send)
    void MonitorSocket::send(Tins::PDU& pdu, int channel) {
        if (detect_injected_) {
            // Set More Data flag so we can detect injected frames
            if (auto* dot11 = pdu.find_pdu<Tins::Dot11>())
                dot11->more_data(1);
        }

        // Wrap in RadioTap if not already present
        if (!pdu.find_pdu<Tins::RadioTap>()) {
            Tins::RadioTap rt{};
            const int freq_mhz = hw_capabilities::channel_to_freq(channel);
            rt.channel(freq_mhz, Tins::RadioTap::OFDM);
            rt.inner_pdu(pdu.clone());
            // TXFlags = NOSEQ+ORDER (0x28) — matches Python RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")
            rt.inner_pdu(pdu.clone());

            sender_.send(rt);
        } else {
            sender_.send(pdu);
        }
    }

    // Receive one frame, stripping FCS if present
    // Returns nullptr if no frame or parse error
    std::unique_ptr<Tins::PDU> MonitorSocket::recv() {
        pcap_pkthdr* header;
        const u_char* frame;
        const int fd = pcap_get_selectable_fd(sniffer_.get_pcap_handle());

        pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, 1) <= 0) return nullptr;
        if (!(pfd.revents & POLLIN)) return nullptr;

        if (pcap_next_ex(sniffer_.get_pcap_handle(), &header, &frame) != 1)
            return nullptr;

        try {
            auto rt = std::make_unique<Tins::RadioTap>(frame, header->caplen);
            strip_fcs(*rt);
            return rt;
        } catch (...) {
            return nullptr;
        }
    }

    Tins::SnifferConfiguration MonitorSocket::make_sniff_cfg() {
        Tins::SnifferConfiguration cfg;
        cfg.set_immediate_mode(true);
        cfg.set_timeout(0);
        return cfg;
    }
    void MonitorSocket::set_filter(const std::string& bpf) {
        sniffer_.set_filter(bpf);
    }

    // Strip FCS if RadioTap FLAGS field indicates it's present
    // Mirrors Python _detect_and_strip_fcs
    void MonitorSocket::strip_fcs(Tins::RadioTap& rt) {
        if (!((rt.present() & Tins::RadioTap::FLAGS) &&
              (rt.flags() & Tins::RadioTap::FCS)))
            return;

        // Reserialize without FCS — libtins handles this internally
        // when FCS flag is set it includes 4 extra bytes at the end
        auto* dot11 = rt.find_pdu<Tins::Dot11>();
        if (!dot11) return;

        const auto raw = dot11->serialize();
        if (raw.size() < 4) return;

        // Rebuild Dot11 without last 4 bytes (FCS)
        try {
            Tins::Dot11* stripped = Tins::Dot11::from_bytes(
                raw.data(), raw.size() - 4);
            rt.inner_pdu(stripped);
        } catch (...) {}
    }
};
