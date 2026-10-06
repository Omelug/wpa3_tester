#pragma once
#include <tins/tins.h>
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "config/RunStatus.h"
#include "attacks/mc_mitm/MonitorSocket.h"

namespace wpa3_tester::ssid_confusion {

class SsidConfusion: public McMitm {
private:
	std::string confused_ssid;
	int beacon_ms;
	int beacon_warn_sec;
public:
	static void translate_data_mac(std::vector<uint8_t>& raw,
							   const Tins::HWAddress<6>& from_bssid,
							   const Tins::HWAddress<6>& to_bssid, bool change_sa = true);
	static std::unique_ptr<Tins::Dot11Beacon> make_confused_beacon(const Tins::Dot11Beacon &real, const std::string &confused_ssid, bool strip_rsn);
	static Tins::Dot11ProbeResponse make_confused_probe_resp(
		const Tins::Dot11ProbeResponse &real, const std::string &confused_ssid, bool strip_rsn);


	SsidConfusion(const ActorPtr &rogue_sta, const ActorPtr &rogue_ap, const ActorPtr &sta, const ActorPtr &ap,
		const std::optional<std::filesystem::path> &run_folder, const std::string & confused_ssid, const int beacon_ms,
		const int beacon_warn_sec):
	McMitm(rogue_sta, rogue_ap, sta, ap, run_folder, false) {
		this->confused_ssid = confused_ssid;
		this->beacon_ms     = beacon_ms;
		this->beacon_warn_sec = beacon_warn_sec;
		//this->netconfig.ssid = rogue_ap->get)(); //TODO needed?
	}

	void run(RunStatus &rs, int timeout_sec) override;
	void send_to_rogue(Tins::PDU &pdu) const override;
	void send_to_rogue(const std::vector<unsigned char> &raw) const override;
	FrameProcess handle_eapol_real(Tins::HWAddress<6> addr1, Tins::HWAddress<6> addr2, Tins::PDU &pdu) const override;
	[[nodiscard]] FrameProcess handle_probe_real(Tins::HWAddress<6> addr2, const Tins::Dot11 &dot11) const override;
	void handle_rx_real_chan(const std::unique_ptr<Tins::PDU> &pdu, const std::vector<unsigned char> &raw) override;
	void send_to_real(Tins::PDU &pdu) const override;
	void send_to_real(const std::vector<unsigned char> &raw) const override;
	FrameProcess handle_probe(Tins::HWAddress<6> addr2, const Tins::PDU *pdu, const Tins::Dot11 &dot11) override;
	FrameProcess handle_open_auth(const Tins::HWAddress<6> &addr2, Tins::Dot11 &dot11) override;
	FrameProcess handle_eapol_rogue(Tins::HWAddress<6> addr1, Tins::HWAddress<6> addr2, Tins::PDU &pdu) const;
	FrameProcess handle_assoc_request(const Tins::HWAddress<6> &addr2, Tins::Dot11 &dot11, const std::vector<uint8_t> &raw) const;
	void handle_rx_rogue_chan(const std::unique_ptr<Tins::PDU> &pdu, const std::vector<unsigned char> &raw) override;

};
}
