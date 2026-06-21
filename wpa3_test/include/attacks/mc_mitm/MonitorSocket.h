#pragma once
#include <chrono>
#include <functional>
#include <libssh/libssh.h>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "system/wifi_channel.h"

namespace wpa3_tester{
class MonitorSocket{
public:
	explicit MonitorSocket(const std::string &iface, bool detect_injected = false);
	MonitorSocket(const std::string &iface, const std::optional<std::string> &netns, bool detect_injected = false);
	// Remote capture: persistent SSH channel from open_capture_channel().
	explicit MonitorSocket(ssh_channel rx_ch, bool detect_injected = false);
	// Remote TX injection: persistent SSH channel running remote_injector.
	struct tag_tx_t{};
	explicit MonitorSocket(ssh_channel tx_ch, tag_tx_t);
	~MonitorSocket();
	MonitorSocket(MonitorSocket &&) noexcept;
	MonitorSocket(const MonitorSocket &) = delete;
	MonitorSocket &operator=(const MonitorSocket &) = delete;
	MonitorSocket &operator=(MonitorSocket &&) = delete;

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
	void recv_loop(std::chrono::steady_clock::time_point deadline, const std::function<bool(RecvResult)> &on_packet);
	pcap_t *get_pcap_handle(){ return sniffer_ ? sniffer_->get_pcap_handle() : nullptr; }
	Tins::Sniffer &sniffer(){ return *sniffer_; }

	void set_filter(const std::string &bpf);
private:
	static Tins::SnifferConfiguration make_sniff_cfg();
	bool detect_injected_;
	std::unique_ptr<Tins::Sniffer> sniffer_; // nullptr when remote
	// Remote capture state (null sniffer_ when set):
	ssh_channel rx_ch_ = nullptr;
	// Remote TX injection channel (null sniffer_ when set):
	ssh_channel tx_ch_ = nullptr;
	std::vector<uint8_t> rx_buf_;
	std::size_t rx_head_ = 0; // read offset into rx_buf_ — no per-packet erase
	bool pcap_hdr_done_ = false;

	void fill_rx_buf();
	RecvResult parse_remote_recv();
public:
	bool mf_workaround = false;
};
}
