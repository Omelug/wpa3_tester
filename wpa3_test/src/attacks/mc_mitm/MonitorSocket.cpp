#include "attacks//mc_mitm/MonitorSocket.h"
#include <arpa/inet.h>
#include <memory>
#include <pcap/pcap.h>
#include <string>
#include <sys/poll.h>
#include <tins/tins.h>

#include "logger/error_log.h"
#include "system/hw_capabilities.h"
#include "system/netlink_guards.h"

using namespace std;
using namespace Tins;

namespace wpa3_tester{
MonitorSocket::MonitorSocket(const string &iface, const bool detect_injected)
: detect_injected_(detect_injected), sniffer_(make_unique<Sniffer>(iface, make_sniff_cfg())){
	char errbuf[PCAP_ERRBUF_SIZE];
	if(pcap_setnonblock(sniffer_->get_pcap_handle(), 1, errbuf) == -1) throw run_err(
		"pcap_setnonblock failed: " + string(errbuf));
}

MonitorSocket::MonitorSocket(const string &iface, const optional<string> &netns, const bool detect_injected)
: detect_injected_(detect_injected){
	netlink_helper::NetNSContext ns_guard(netns);
	sniffer_ = make_unique<Sniffer>(iface, make_sniff_cfg());
	char errbuf[PCAP_ERRBUF_SIZE];
	if(pcap_setnonblock(sniffer_->get_pcap_handle(), 1, errbuf) == -1)
		throw run_err("pcap_setnonblock failed: " + string(errbuf));
}

MonitorSocket::MonitorSocket(const ssh_channel rx_ch, const bool detect_injected)
: detect_injected_(detect_injected), rx_ch_(rx_ch){}

MonitorSocket::MonitorSocket(const ssh_channel tx_ch, tag_tx_t)
: detect_injected_(false), tx_ch_(tx_ch){}

MonitorSocket::~MonitorSocket(){
	if(rx_ch_){
		ssh_channel_send_eof(rx_ch_);
		ssh_channel_close(rx_ch_);
		ssh_channel_free(rx_ch_);
	}
	if(tx_ch_){
		ssh_channel_send_eof(tx_ch_);
		ssh_channel_close(tx_ch_);
		ssh_channel_free(tx_ch_);
	}
}

MonitorSocket::MonitorSocket(MonitorSocket &&o) noexcept
: detect_injected_(o.detect_injected_), sniffer_(std::move(o.sniffer_)),
rx_ch_(exchange(o.rx_ch_, nullptr)), tx_ch_(exchange(o.tx_ch_, nullptr)),
rx_buf_(std::move(o.rx_buf_)),
rx_head_(o.rx_head_), pcap_hdr_done_(o.pcap_hdr_done_), mf_workaround(o.mf_workaround){}

static void write_to_inject_channel(ssh_channel ch, const vector<uint8_t> &bytes){
	const uint16_t len_be = htons(static_cast<uint16_t>(bytes.size()));
	ssh_channel_write(ch, &len_be, 2);
	ssh_channel_write(ch, bytes.data(), static_cast<uint32_t>(bytes.size()));
}

// Send with RadioTap TXFlags=NOSEQ+ORDER (matches Python MonitorSocket.send)
void MonitorSocket::send(PDU &pdu, const Channel &){
	if(rx_ch_) throw run_err("MonitorSocket::send called on remote-capture-only socket");
	if(detect_injected_){
		// Set More Data flag so we can detect injected frames
		if(auto *dot11 = pdu.find_pdu<Dot11>()) dot11->more_data(1);
	}

	// wrap in RadioTap if not already present.
	// keep the header minimal (only TXFlags) — matching Python behavior.
	// adding CHANNEL field breaks ORDER flag scheduling on some drivers (ath9k_htc).
	vector<uint8_t> bytes;
	if(!pdu.find_pdu<RadioTap>()){
		RadioTap rt{};
		rt.tx_flags(0x28); // NOSEQ|ORDER //FIXME NOSEQ a NO ACk se někdy asi mění,
		rt.inner_pdu(RawPDU(pdu.serialize()));
		bytes = rt.serialize();
	} else{
		pdu.find_pdu<RadioTap>(); //->tx_flags(0x28); //TODO pročNOACK flag??????
		bytes = pdu.serialize();
	}
	if(tx_ch_){
		write_to_inject_channel(tx_ch_, bytes);
		return;
	}
	pcap_inject(sniffer_->get_pcap_handle(), bytes.data(), bytes.size());
}

vector<uint8_t> MonitorSocket::build_inject_frame(const vector<uint8_t> &raw, const Channel &ch,
												const bool detect_injected
){
	if(raw.size() < 4) return {};

	const uint16_t rt_len = raw[2] | (static_cast<uint16_t>(raw[3]) << 8);
	if(raw.size() < rt_len) return {};

	vector out(raw); // copy entire frame, RT header untouched

	// Patch channel frequency in-place inside the existing RT header
	const int freq_mhz = hw_capabilities::channel_to_freq(ch);
	const uint8_t freq_lo = freq_mhz & 0xFF;
	const uint8_t freq_hi = (freq_mhz >> 8) & 0xFF;

	// Walk RT present fields to find channel field offset
	// Present flags start at byte 4, each 4 bytes, bit 3 = Channel
	size_t pos = 8; // skip revision(1) + pad(1) + length(2) + present(4)
	uint32_t present = raw[4] | (raw[5] << 8) | (raw[6] << 16) | (raw[7] << 24);

	// Skip extended present words (bit 31 = another present word follows)
	while(present & (1u << 31)){
		present = raw[pos] | (raw[pos + 1] << 8) | (raw[pos + 2] << 16) | (raw[pos + 3] << 24);
		pos += 4;
	}

	// Walk fields in order until Channel (bit 3)
	if(present & 1u << 0) pos += 8; // TSFT: 8 bytes
	if(present & 1u << 1) pos += 1; // Flags: 1 byte
	if(present & 1u << 2) pos += 1; // Rate: 1 byte
	if(present & 1u << 3){          // Channel: freq(2) + flags(2)
		// Align to 2 bytes
		if(pos % 2 != 0) pos++;
		if(pos + 2 <= rt_len){
			out[pos] = freq_lo;
			out[pos + 1] = freq_hi;
		}
	}

	if(detect_injected && out.size() > static_cast<size_t>(rt_len) + 1) out[rt_len + 1] |= 0x20;

	return out;
}

void MonitorSocket::send(const vector<unsigned char> &raw, const Channel &ch){
	if(rx_ch_) throw run_err("MonitorSocket::send called on remote-capture-only socket");
	const auto out = build_inject_frame(raw, ch, detect_injected_);
	if(out.empty()) return;
	if(tx_ch_){
		write_to_inject_channel(tx_ch_, out);
		return;
	}
	pcap_inject(sniffer_->get_pcap_handle(), out.data(), out.size());
}

MonitorSocket::RecvResult MonitorSocket::parse_frame(const u_char *frame, const uint32_t caplen){
	try{
		const RadioTap rt(frame, caplen);
		uint32_t strip = 0;
		if(rt.present() & RadioTap::FLAGS && (rt.flags() & RadioTap::FCS)) strip = 4;
		auto pdu = make_unique<RadioTap>(frame, caplen - strip);
		return {std::move(pdu), vector(frame, frame + caplen - strip)};
	} catch(...){
		return {};
	}
}

MonitorSocket::RecvResult MonitorSocket::recv(){
	if(rx_ch_){
		fill_rx_buf();
		return parse_remote_recv();
	}
	pcap_pkthdr *header;
	const u_char *frame;
	const int ret = pcap_next_ex(sniffer_->get_pcap_handle(), &header, &frame);
	if(ret <= 0) return {};
	return parse_frame(frame, header->caplen);
}

void MonitorSocket::recv_loop(const chrono::steady_clock::time_point deadline,
							const function<bool(RecvResult)> &on_packet
){
	if(rx_ch_){
		while(true){
			const int rem = static_cast<int>(chrono::duration_cast<chrono::milliseconds>(
				deadline - chrono::steady_clock::now()).count());
			if(rem <= 0) break;
			// Block until data arrives or timeout; 50 ms slices to recheck deadline
			const int avail = ssh_channel_poll_timeout(rx_ch_, min(rem, 50), 0);
			if(avail == SSH_ERROR) break;
			fill_rx_buf();                      // single fill per poll cycle
			while(auto r = parse_remote_recv()) // drain without re-reading SSH channel
				if(on_packet(std::move(r))) return;
		}
		return;
	}
	const int fd = pcap_get_selectable_fd(get_pcap_handle());
	pollfd pfd{fd, POLLIN, 0};
	while(true){
		const int rem = static_cast<int>(chrono::duration_cast<chrono::milliseconds>(
			deadline - chrono::steady_clock::now()).count());
		if(rem <= 0 || poll(&pfd, 1, rem) <= 0) break;
		if(auto r = recv(); r && on_packet(std::move(r))) break;
	}
}

void MonitorSocket::set_filter(const string &bpf){
	if(sniffer_) sniffer_->set_filter(bpf);
}

SnifferConfiguration MonitorSocket::make_sniff_cfg(){
	SnifferConfiguration cfg;
	cfg.set_immediate_mode(true);
	cfg.set_timeout(1); //FIXME prej bug, neblokující nastaveno v pcap_setnonblock
	//cfg.set_promisc_mode(true);
	return cfg;
}

void MonitorSocket::fill_rx_buf(){
	char tmp[4096];
	int n;
	while((n = ssh_channel_read_nonblocking(rx_ch_, tmp, sizeof(tmp), 0)) > 0)
		rx_buf_.insert(rx_buf_.end(), tmp, tmp + n);
}

MonitorSocket::RecvResult MonitorSocket::parse_remote_recv(){
	const uint8_t *buf = rx_buf_.data() + rx_head_;
	size_t avail = rx_buf_.size() - rx_head_;

	if(!pcap_hdr_done_){
		if(avail < 24) return {};
		rx_head_ += 24; buf += 24; avail -= 24;
		pcap_hdr_done_ = true;
	}
	// pcap packet record: ts_sec(4) ts_usec(4) caplen(4) len(4)
	if(avail < 16) return {};
	uint32_t caplen;
	memcpy(&caplen, buf + 8, 4); // both sides LE (OpenWrt + x86)
	if(avail < 16 + caplen) return {};
	auto r = parse_frame(buf + 16, caplen);
	rx_head_ += 16 + caplen;
	// Compact once head grows large — one memcpy beats per-packet erase
	if(rx_head_ > 65536){
		rx_buf_.erase(rx_buf_.begin(), rx_buf_.begin() + static_cast<ptrdiff_t>(rx_head_));
		rx_head_ = 0;
	}
	return r;
}
}