#pragma once
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include "system/wifi_channel.h"

namespace wpa3_tester{
class MonitorSocket{
public:
	explicit MonitorSocket(const std::string &iface, bool detect_injected = false);
	MonitorSocket(const std::string &iface, const std::optional<std::string> &netns, bool detect_injected = false);

	struct RecvResult{
		std::unique_ptr<Tins::PDU> pdu;
		std::vector<uint8_t> raw;
		explicit operator bool() const{ return pdu != nullptr || !raw.empty(); }
	};

	void send(Tins::PDU &pdu, const Channel &ch);
	static std::vector<uint8_t> build_inject_frame(const std::vector<uint8_t> &raw, const Channel &ch,
													bool detect_injected = false
	);
	void send(const std::vector<unsigned char> &raw, const Channel &ch);
	static RecvResult parse_frame(const u_char *frame, uint32_t caplen);
	RecvResult recv();
	void recv_loop(std::chrono::steady_clock::time_point deadline,
	               const std::function<bool(RecvResult)> &on_packet);
	pcap_t *get_pcap_handle(){ return sniffer_.get_pcap_handle(); }
	Tins::Sniffer &sniffer(){ return sniffer_; }

	void set_filter(const std::string &bpf);
private:
	static Tins::SnifferConfiguration make_sniff_cfg();
	bool detect_injected_;
	Tins::Sniffer sniffer_;
public:
	bool mf_workaround = false;
};
}