#include "attacks//mc_mitm/MonitorSocket.h"
#include "net_parser/dot11_defs.h"
#include <memory>
#include <pcap/pcap.h>
#include <string>
#include <sys/poll.h>
#include <tins/tins.h>

#include "attacks/mc_mitm/wifi_util.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "system/netlink_guards.h"

using namespace std;
using namespace Tins;

namespace wpa3_tester {
MonitorSocket::MonitorSocket(const string &iface, const optional<string> &netns){
	netlink_helper::NetNSContext ns_guard(netns);
	sniffer_ = make_unique<Sniffer>(iface, make_sniff_cfg());
	char errbuf[PCAP_ERRBUF_SIZE];
	if(pcap_setnonblock(sniffer_->get_pcap_handle(), 1, errbuf) == -1)
		throw run_err("pcap_setnonblock failed: " + string(errbuf));
}

MonitorSocket::MonitorSocket(const ssh_channel rx_ch):
	rx_ch_(rx_ch) {}

MonitorSocket::MonitorSocket(const ssh_channel tx_ch, tag_tx_t):
	tx_ch_(tx_ch) {}

MonitorSocket::~MonitorSocket() {
	if(rx_ch_) {
		ssh_channel_send_eof(rx_ch_);
		ssh_channel_close(rx_ch_);
		ssh_channel_free(rx_ch_);
	}
	if(tx_ch_) {
		ssh_channel_send_eof(tx_ch_);
		ssh_channel_close(tx_ch_);
		ssh_channel_free(tx_ch_);
	}
}

MonitorSocket::MonitorSocket(MonitorSocket &&o) noexcept:
	sniffer_(std::move(o.sniffer_)),
	rx_ch_(exchange(o.rx_ch_, nullptr)),
	tx_ch_(exchange(o.tx_ch_, nullptr)),
	rx_buf_(std::move(o.rx_buf_)),
	rx_head_(o.rx_head_),
	pcap_hdr_done_(o.pcap_hdr_done_),
	mf_workaround(o.mf_workaround) {}

static void write_to_inject_channel(const ssh_channel ch, const frame_raw_t &bytes) {
	const uint16_t len_be = htons(static_cast<uint16_t>(bytes.size()));
	ssh_channel_write(ch, &len_be, 2);
	ssh_channel_write(ch, bytes.data(), static_cast<uint32_t>(bytes.size()));
}

void MonitorSocket::send(PDU &pdu, const Channel &, const uint16_t tx_flags) const {
	if(rx_ch_) throw run_err("MonitorSocket::send called on remote-capture-only socket");

	frame_raw_t frame_raw;
	if(!pdu.find_pdu<RadioTap>()) {
		RadioTap rt{};
		rt.tx_flags(tx_flags);
		rt.inner_pdu(RawPDU(pdu.serialize()));
		frame_raw = rt.serialize();
	} else {
		pdu.find_pdu<RadioTap>()->tx_flags(tx_flags);
		frame_raw = pdu.serialize();
	}
	if(tx_ch_) {
		write_to_inject_channel(tx_ch_, frame_raw);
		return;
	}
	pcap_inject(sniffer_->get_pcap_handle(), frame_raw.data(), frame_raw.size());
}

frame_raw_t MonitorSocket::build_inject_frame(
	const frame_raw_t &frame_raw, const Channel &) {
	const uint16_t init_rt_len = radiotap::get_rt_len(frame_raw);
	if(!init_rt_len) return {};
	// guard against malformed it_len when frame is a radiotap capture
	if(frame_raw[0] == PKTHDR_RADIOTAP_VERSION && init_rt_len >= frame_raw.size()) {
		log(LogLevel::WARNING, "build_inject_frame: malformed RadioTap rt_len={} >= frame size={}, dropping", init_rt_len, frame_raw.size());
		return {};
	}

	const auto with_rt = ensure_radiotap(frame_raw);

	// Strip RX RT metadata, always inject with fresh minimal TX RT (NOACK|ORDER).
	const uint16_t rt_len = radiotap::get_rt_len(with_rt);
	if(!rt_len || rt_len >= with_rt.size()) return {};

	RadioTap rt{};
	rt.tx_flags(radiotap::TX_NOACK | radiotap::TX_ORDER);
	rt.inner_pdu(RawPDU(with_rt.data() + rt_len, with_rt.size() - rt_len));
	return rt.serialize();
}

void MonitorSocket::send(const vector<unsigned char> &raw, const Channel &ch) const {
	if(rx_ch_) throw run_err("MonitorSocket::send called on remote-capture-only socket");
	const auto out = build_inject_frame(raw, ch);
	if(out.empty()) return;
	if(tx_ch_) {
		write_to_inject_channel(tx_ch_, out);
		return;
	}
	pcap_inject(sniffer_->get_pcap_handle(), out.data(), out.size());
}

MonitorSocket::RecvResult MonitorSocket::parse_frame(const frame_raw_t &frame) {
	try {
		const RadioTap rt(frame.data(), frame.size());
		uint32_t strip = 0; // delete FCS
		if(rt.present() & RadioTap::FLAGS && (rt.flags() & RadioTap::FCS)) strip = 4;
		auto pdu = make_unique<RadioTap>(frame.data(), frame.size() - strip);
		return { std::move(pdu), vector(frame.begin(), frame.end() - strip) };
	} catch(const exception &e) {
		// Data frames: libtins throws when building SNAP/EAPOL inner PDU.
		// Parse just the 802.11 header (no inner PDU) so addr extraction and relay still work.
		const uint16_t rt_len = radiotap::get_rt_len(frame);
		if(rt_len && rt_len + dot11::DUR_OFFSET <= frame.size()) { // fc0+fc1 (Frame Control = 2 bytes)
			const uint8_t fc0 = frame[rt_len];
			const uint8_t fc1 = frame[rt_len + 1];
			if((fc0 >> dot11::FC_TYPE_SHIFT & dot11::FC_TYPE_MASK) == dot11::TYPE_DATA) {
				const bool qos     = (fc0 & 0x80) != 0;
				const bool has_4addr = (fc1 & 0x03) == 0x03;
				const size_t hdr  = dot11::MGMT_HDR_SIZE + (qos ? 2u : 0u) + (has_4addr ? 6u : 0u);
				const size_t trunc = rt_len + hdr;
				if(trunc <= frame.size()) {
					try {
						auto pdu = make_unique<RadioTap>(frame.data(), trunc);
						// Reparse RT header only to check FCS flag (libtins threw on inner PDU, not RT).
						uint32_t strip = 0;
						try {
							const RadioTap rt2(frame.data(), rt_len);
							if(rt2.present() & RadioTap::FLAGS && (rt2.flags() & RadioTap::FCS)) strip = 4;
						} catch(...) {}
						log(LogLevel::DEBUG, "SNAP/EAPOL inner PDU, type=0x{:02x}", trunc < frame.size() ? frame[trunc + 1] : 0xFF);
						return { std::move(pdu), vector(frame.begin(), frame.end() - strip) };
					} catch(...) {
						log(LogLevel::ERROR, "parse_frame: SNAP/EAPOL inner PDU");
						return {};
					}
				}
			}
		}
		log(LogLevel::DEBUG, "parse_frame: {}", e.what());
	} catch(...) {
		log(LogLevel::DEBUG, "parse_frame: unknown exception");
	}
	return {};
}

MonitorSocket::RecvResult MonitorSocket::recv() {
	if(rx_ch_) {
		fill_rx_buf();
		return parse_remote_recv();
	}
	pcap_pkthdr *header;
	const u_char *frame;
	const int ret = pcap_next_ex(sniffer_->get_pcap_handle(), &header, &frame);
	if(ret <= 0) return {};
	return parse_frame(frame_raw_t(frame, frame + header->caplen));
}

void MonitorSocket::recv_loop(
	const chrono::steady_clock::time_point deadline, const function<bool(RecvResult)> &on_frame) {
	if(rx_ch_) {
		while(true) {
			const int rem = static_cast<int>(
				chrono::duration_cast<chrono::milliseconds>(deadline - chrono::steady_clock::now()).count());
			if(rem <= 0) break;
			// Block until data arrives or timeout; 50 ms slices to recheck deadline
			const int avail = ssh_channel_poll_timeout(rx_ch_, min(rem, 50), 0);
			if(avail == SSH_ERROR) break;
			fill_rx_buf();						// single fill per poll cycle
			while(auto r = parse_remote_recv()) // drain without re-reading SSH channel
				if(on_frame(std::move(r))) return;
		}
		return;
	}
	const int fd = pcap_get_selectable_fd(get_pcap_handle());
	pollfd pfd{ fd, POLLIN, 0 };
	while(true) {
		const int rem = static_cast<int>(
			chrono::duration_cast<chrono::milliseconds>(deadline - chrono::steady_clock::now()).count());
		if(rem <= 0 || poll(&pfd, 1, rem) <= 0) break;
		if(auto r = recv(); r && on_frame(std::move(r))) break;
	}
}
//TODO test in sim possible?
uint32_t MonitorSocket::log_drops(const char *tag) const {
	if(!sniffer_) return 0;
	pcap_stat ps{};
	if(pcap_stats(sniffer_->get_pcap_handle(), &ps) != 0) return 0;
	if(ps.ps_drop > last_drops_)
		log(LogLevel::WARNING, "{}: pcap kernel_drops={} iface_drops={}", tag, ps.ps_drop, ps.ps_ifdrop);
	last_drops_ = ps.ps_drop;
	return ps.ps_drop;
}

void MonitorSocket::set_filter(const string &bpf) const {
	if(!sniffer_) throw run_err("set_filter: not supported on remote socket");
	pcap_t *handle = sniffer_->get_pcap_handle();
	if (!handle) {
		throw run_err("set_filter: pcap handle is null or not initialized");
	}

	const int dlt = pcap_datalink(handle);
	if (dlt != DLT_IEEE802_11_RADIO) {
		throw run_err("set_filter: no DLT_IEEE802_11_RADIO (got dlt = {})", dlt);
	}

	if(!bpf.empty()) {
		bpf_program prog{};
		if(pcap_compile(handle, &prog, bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
			throw run_err("set_filter: pcap_compile failed (dlt={}): {}", pcap_datalink(handle), pcap_geterr(handle));
		}
		if(prog.bf_len <= 1)
			log(LogLevel::WARNING, "set_filter: '{}' compiled to {} instruction(s) - DLT mismatch?", bpf, prog.bf_len);
		pcap_freecode(&prog);
	}

	if(!sniffer_->set_filter(bpf))  throw run_err("set_filter: compilation error");
}

SnifferConfiguration MonitorSocket::make_sniff_cfg() {
	SnifferConfiguration cfg;
	cfg.set_immediate_mode(true); // deliver each packet immediately, timeout is irrelevant
	cfg.set_timeout(10); // immediate_mode don't work on really old kernels (< 3.2), for sure //TODO hardocded
	return cfg;
}

void MonitorSocket::fill_rx_buf() {
	char tmp[4096];
	int n;
	while((n = ssh_channel_read_nonblocking(rx_ch_, tmp, sizeof(tmp), 0)) > 0)
		rx_buf_.insert(rx_buf_.end(), tmp, tmp + n);
}

MonitorSocket::RecvResult MonitorSocket::parse_remote_recv() {
	// pcap file format: global header followed by packet records
	// pcap_pkthdr uses struct timeval (16B on 64-bit), so its sizeof != wire format; use explicit constants
	constexpr size_t PCAP_PKT_HDR    = 16; // wire: ts_sec(4)+ts_usec(4)+caplen(4)+len(4)
	constexpr size_t PCAP_CAPLEN_OFF =  8; // offset of caplen within wire packet record

	const uint8_t *buf = rx_buf_.data() + rx_head_;
	size_t avail = rx_buf_.size() - rx_head_;
	if(!pcap_hdr_done_) {
		constexpr size_t PCAP_GLOBAL_HDR = sizeof(pcap_file_header);
		if(avail < PCAP_GLOBAL_HDR) return {};
		rx_head_ += PCAP_GLOBAL_HDR;
		buf      += PCAP_GLOBAL_HDR;
		avail    -= PCAP_GLOBAL_HDR;
		pcap_hdr_done_ = true;
	}
	if(avail < PCAP_PKT_HDR) return {};
	uint32_t caplen;
	memcpy(&caplen, buf + PCAP_CAPLEN_OFF, sizeof(caplen)); // both sides LE (OpenWrt + x86)
	if(avail < PCAP_PKT_HDR + caplen) return {};
	auto r = parse_frame(frame_raw_t(buf + PCAP_PKT_HDR, buf + PCAP_PKT_HDR + caplen));
	rx_head_ += 16 + caplen;
	// compact once head grows large - one memcpy beats per-packet erase
	if(rx_head_ > 65536) {
		rx_buf_.erase(rx_buf_.begin(), rx_buf_.begin() + static_cast<ptrdiff_t>(rx_head_));
		rx_head_ = 0;
	}
	return r;
}
}
