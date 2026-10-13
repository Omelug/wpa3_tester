#pragma once
#include <chrono>
#include <functional>
#include <libssh/libssh.h>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "config/RunStatus.h"
#include "system/wifi_channel.h"

namespace wpa3_tester {
class MonitorSocket {
public:
	MonitorSocket(const std::string &iface, const std::optional<std::string> &netns);
	// Remote capture: persistent SSH channel from open_capture_channel()
	explicit MonitorSocket(ssh_channel rx_ch);

	// Remote TX injection: persistent SSH channel running remote_injector
	struct tag_tx_t {};
	explicit MonitorSocket(ssh_channel tx_ch, tag_tx_t);
	~MonitorSocket();
	MonitorSocket(MonitorSocket &&) noexcept;
	MonitorSocket(const MonitorSocket &) = delete;
	MonitorSocket &operator=(const MonitorSocket &) = delete;
	MonitorSocket &operator=(MonitorSocket &&) = delete;

	struct RecvResult {
		std::unique_ptr<Tins::PDU> pdu;
		std::vector<uint8_t> raw;
		explicit operator bool() const { return pdu != nullptr || !raw.empty(); }
	};

	void send(Tins::PDU &pdu, const Channel &ch) const;
	static frame_raw_t build_inject_frame(
		const frame_raw_t &raw, const Channel &ch);
	void send(const frame_raw_t &raw, const Channel &ch) const;
	static RecvResult parse_frame(const frame_raw_t &frame);
	RecvResult recv();
	void recv_loop(std::chrono::steady_clock::time_point deadline, const std::function<bool(RecvResult)> &on_frame);
	pcap_t *get_pcap_handle() const { return sniffer_ ? sniffer_->get_pcap_handle() : nullptr; }
	Tins::Sniffer &sniffer() const { return *sniffer_; }

	void set_filter(const std::string &bpf) const;
private:
	static Tins::SnifferConfiguration make_sniff_cfg();
	std::unique_ptr<Tins::Sniffer> sniffer_; // nullptr when remote
	//  capture state (null sniffer_ when set)
	ssh_channel rx_ch_ = nullptr;
	// Remote TX injection channel (null sniffer_ when set)
	ssh_channel tx_ch_ = nullptr;
	std::vector<uint8_t> rx_buf_;
	std::size_t rx_head_ = 0; // read offset into rx_buf_ - no per-packet erase
	bool pcap_hdr_done_ = false;

	void fill_rx_buf();
	RecvResult parse_remote_recv();
public:
	bool mf_workaround = false;
};
}
