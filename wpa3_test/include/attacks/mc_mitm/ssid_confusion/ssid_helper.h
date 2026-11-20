#pragma once
#include <optional>
#include <tins/tins.h>
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "config/RunStatus.h"

namespace wpa3_tester::ssid_confusion {

class SsidConfusion: public McMitm {
	std::string confused_ssid;
	int beacon_ms;
public:
	static std::unique_ptr<Tins::Dot11Beacon> make_confused_beacon(const Tins::Dot11Beacon &real,
		const Tins::HWAddress<6> &rogue_mac, const Channel &rogue_ch,
		const std::optional<std::string> &confused_ssid = std::nullopt);

	SsidConfusion(const ActorPtr &rogue_sta, const ActorPtr &rogue_ap, const ActorPtr &sta, const ActorPtr &ap,
		const std::optional<std::filesystem::path> &run_folder, const std::string & confused_ssid, const int beacon_ms):
	McMitm(rogue_sta, rogue_ap, sta, ap, run_folder, false) {
		this->confused_ssid = confused_ssid;
		this->beacon_ms     = beacon_ms;
		this->only_to_mitm = false; // have no effect
	}

	void run(RunStatus &rs, int timeout_sec) override;
	void send_to_rogue(Tins::PDU &pdu) const override;
	void send_to_rogue(const frame_raw_t &raw) const override;
	[[nodiscard]] FrameProcess handle_eapol_real(Tins::HWAddress<6> addr2, const Tins::PDU &pdu, const frame_raw_t &raw) const;
	[[nodiscard]] FrameProcess handle_mgmt_action_real(Tins::HWAddress<6> addr1, const Tins::Dot11 &dot11, const frame_raw_t &raw) const;
	[[nodiscard]] FrameProcess handle_assoc_real(Tins::HWAddress<6> addr1, const Tins::PDU &pdu, const frame_raw_t &raw) const;
	[[nodiscard]] FrameProcess handle_probe_real(Tins::HWAddress<6> addr2, const Tins::Dot11 &dot11);
	void handle_rx_real_chan(const std::unique_ptr<Tins::PDU> &pdu, const frame_raw_t &raw) override;

	void send_to_real(Tins::PDU &pdu) const override;
	void send_to_real(const frame_raw_t &raw) const override;
	FrameProcess handle_probe(Tins::HWAddress<6> addr2, const Tins::PDU *pdu, const Tins::Dot11 &dot11) override;
	FrameProcess handle_open_auth(const Tins::HWAddress<6> &addr2, Tins::Dot11 &dot11) override;
	[[nodiscard]] FrameProcess handle_eapol_rogue(Tins::HWAddress<6> addr2, const Tins::PDU &pdu, const frame_raw_t &raw) const;
	void send_synth_assoc_resp(const Tins::HWAddress<6> &sta_mac) const;
	FrameProcess handle_assoc_request(const Tins::HWAddress<6> &addr2, Tins::Dot11 &dot11, const frame_raw_t &raw);
	[[nodiscard]] FrameProcess handle_mgmt_action_rogue(Tins::HWAddress<6> addr2, const Tins::Dot11 &dot11, const frame_raw_t &raw) const;
	void handle_rx_rogue_chan(const std::unique_ptr<Tins::PDU> &pdu, const frame_raw_t &raw) override;

};
}
