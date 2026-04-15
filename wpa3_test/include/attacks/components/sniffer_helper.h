#pragma once
#include <pcap/pcap.h>
#include <cerrno>
#include "system/hw_capabilities.h"
#include "inteprrupt.h"
#include <sys/poll.h>
#include <tins/pdu.h>
#include "logger/log.h"

enum class StopReason { Timeout, HandlerDone, Interrupted };

// -1 = no limit
namespace wpa3_tester::components{
    template<typename T, typename Handler>
        std::variant<T, StopReason> poll_sniffer(
        pcap_t* handle,
        const int timeout_ms,
        Handler&& on_packet)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_setnonblock(handle, 1, errbuf);
        const int pcap_fd = pcap_get_selectable_fd(handle);
        if (pcap_fd == -1) throw std::runtime_error("pcap fd not selectable");

        pollfd pfds[2] = {
            { .fd = pcap_fd,   .events = POLLIN, .revents = 0 },
            { .fd = g_interrupt_pipe.read_fd, .events = POLLIN, .revents = 0 },
        };

        const auto deadline = (timeout_ms >= 0)
            ? std::optional{std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms)}
        : std::nullopt;

        while (true) {
            int remaining_ms = -1;
            if (deadline) {
                remaining_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    *deadline - std::chrono::steady_clock::now()).count());
                if (remaining_ms <= 0) return StopReason::Timeout;
            }

            const int ret = poll(pfds, 2, remaining_ms);

            if (ret < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error("poll error: " + std::to_string(errno));
            }

            if (pfds[1].revents & POLLIN) return StopReason::Interrupted;
            if (ret == 0)                 return StopReason::Timeout;

            pcap_pkthdr* hdr;
            const uint8_t* pkt;
            while (pcap_next_ex(handle, &hdr, &pkt) == 1) {
                if (auto result = on_packet(pkt, hdr->caplen))
                    return move(*result);
            }
        }
    }

    template<typename T, typename Handler>
    std::variant<T, StopReason> poll_sniffer_pdu(
        Handler&& on_packet,
        const std::string& interface,
        const std::string& filter = "",
        const int timeout_sec = -1
        )
    {
        Tins::SnifferConfiguration sniff_config;
        sniff_config.set_timeout(100);
        sniff_config.set_immediate_mode(true);
        sniff_config.set_filter(filter);

        log(LogLevel::INFO, "Scanning with "+ filter);
        Tins::Sniffer sniffer(interface, sniff_config);

        const int pcap_fd = pcap_get_selectable_fd(sniffer.get_pcap_handle());
        if (pcap_fd == -1) throw std::runtime_error("pcap fd not selectable");

        pollfd pfds[2] = {
            { .fd = pcap_fd,                  .events = POLLIN, .revents = 0 },
            { .fd = g_interrupt_pipe.read_fd, .events = POLLIN, .revents = 0 },
        };

        const auto deadline = (timeout_sec >= 0)
            ? std::optional{std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec)}
        : std::nullopt;

        while (true) {
            int remaining_ms = -1;
            if (deadline) {
                remaining_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    *deadline - std::chrono::steady_clock::now()).count());
                if (remaining_ms <= 0) return StopReason::Timeout;
            }

            const int ret = poll(pfds, 2, remaining_ms);

            if (ret < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error("poll error: " + std::to_string(errno));
            }

            if (pfds[1].revents & POLLIN)
                return StopReason::Interrupted;
            if (ret == 0 || !(pfds[0].revents & POLLIN)) continue;

            if (pfds[0].revents & POLLIN) {
                if (const std::unique_ptr<Tins::PDU> pdu{sniffer.next_packet()}) {
                    if (auto result = on_packet(*pdu))
                        return move(*result);
                }
            }
        }
    }
}