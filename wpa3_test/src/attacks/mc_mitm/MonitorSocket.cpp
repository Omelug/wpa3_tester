#include "attacks//mc_mitm/MonitorSocket.h"
#include <memory>
#include <string>
#include <tins/tins.h>

#include "logger/error_log.h"
#include "system/hw_capabilities.h"
#include "system/netlink_guards.h"

using namespace std;
using namespace Tins;

namespace wpa3_tester{
MonitorSocket::MonitorSocket(const string &iface, const bool detect_injected)
: detect_injected_(detect_injected), sniffer_(iface, make_sniff_cfg()){
	char errbuf[PCAP_ERRBUF_SIZE];
	if(pcap_setnonblock(sniffer_.get_pcap_handle(), 1, errbuf) == -1) throw run_err(
		"pcap_setnonblock failed: " + string(errbuf));
}

MonitorSocket::MonitorSocket(const string &iface, const optional<string> &netns, const bool detect_injected)
: detect_injected_(detect_injected), sniffer_([&]() {
	netlink_helper::NetNSContext ns_guard(netns);
	return Sniffer(iface, make_sniff_cfg());
}()){
	char errbuf[PCAP_ERRBUF_SIZE];
	if(pcap_setnonblock(sniffer_.get_pcap_handle(), 1, errbuf) == -1) throw run_err(
		"pcap_setnonblock failed: " + string(errbuf));
}

// Send with RadioTap TXFlags=NOSEQ+ORDER (matches Python MonitorSocket.send)
void MonitorSocket::send(PDU &pdu, const Channel &){
	if(detect_injected_){
		// Set More Data flag so we can detect injected frames
		if(auto *dot11 = pdu.find_pdu<Dot11>()) dot11->more_data(1);
	}

	// Wrap in RadioTap if not already present.
	// Keep the header minimal (only TXFlags) — matching Python behavior.
	// Adding CHANNEL field breaks ORDER flag scheduling on some drivers (ath9k_htc).
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
	pcap_inject(sniffer_.get_pcap_handle(), bytes.data(), bytes.size());
}

vector<uint8_t> MonitorSocket::build_inject_frame(const vector<uint8_t> &raw, const Channel &ch,
												const bool detect_injected){
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
	const auto out = build_inject_frame(raw, ch, detect_injected_);
	if(out.empty()) return;
	pcap_inject(sniffer_.get_pcap_handle(), out.data(), out.size());
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
	pcap_pkthdr *header;
	const u_char *frame;
	const int ret = pcap_next_ex(sniffer_.get_pcap_handle(), &header, &frame);
	if(ret <= 0) return {};
	return parse_frame(frame, header->caplen);
}

void MonitorSocket::set_filter(const string &bpf){ sniffer_.set_filter(bpf); }

SnifferConfiguration MonitorSocket::make_sniff_cfg(){
	SnifferConfiguration cfg;
	cfg.set_immediate_mode(true);
	cfg.set_timeout(1); //FIXME prej bug, neblokující nastaveno v pcap_setnonblock
	//cfg.set_promisc_mode(true);
	return cfg;
}
}