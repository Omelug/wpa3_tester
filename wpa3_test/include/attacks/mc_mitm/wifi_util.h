#pragma once
#include <algorithm>
#include <cstdint>
#include <string>
#include <tins/tins.h>
#include <vector>
#include "config/RunStatus.h"
#include "net_parser/dot11_defs.h"
#include "net_parser/eap_defs.h"
#include "system/wifi_channel.h"
namespace wpa3_tester {
using eap::EapolMsg;
using eap::eapol_msg_labels;
int get_channel(const std::string &iface);
int chan2freq(Channel ch);
std::string get_ssid(const Tins::Dot11Beacon &beacon);
struct Dot11Addrs {
	Tins::HWAddress<6> addr1;
	Tins::HWAddress<6> addr2;
};
Dot11Addrs get_addrs(const Tins::PDU &pdu, const frame_raw_t &raw);
Tins::Dot11ProbeResponse beacon_to_probe_resp(const Tins::Dot11Beacon &beacon, const Channel &rogue_channel);
void patch_ht_operation_in_frame(frame_raw_t &raw, uint8_t channel);
bool is_eapol(const Tins::PDU &pdu);
EapolMsg get_eapol_msg_num(const frame_raw_t &raw, bool print = false);
std::string eap_description(const Tins::PDU &pdu);
// return raw bytes guaranteed to start with a RadioTap header
// idempotent: if RT is already present, returns the input unchanged
// throw run_err if bytes are not a valid 802.11 frame (not valid after add of radiotap)
frame_raw_t ensure_radiotap(const frame_raw_t &raw);
Tins::Dot11Beacon append_csa(const Tins::Dot11Beacon &beacon, const Channel &new_channel, uint8_t count = 1);
// EAPOL helpers
uint64_t get_eapol_replay_num(const Tins::Dot11Data &frame);
void start_ap(RunStatus &rs, const std::string &ap_iface, const ActorPtr &base_actor, const Channel &channel,
	const Tins::Dot11Beacon &beacon, std::optional<Tins::HWAddress<6>> mac = std::nullopt, int interval = 100,
	int dtim_period = 1);
void start_ap_hostapd(RunStatus &rs, const std::string &ap_iface, const ActorPtr &base_actor, const Channel &channel,
	std::optional<Tins::HWAddress<6>> bssid = std::nullopt);
void stop_ap(const std::string &iface, const std::optional<std::string> &netns);
void set_station_authorized(const std::string &ap_iface, const Tins::HWAddress<6> &mac, const std::optional<std::string> &netns);
void add_station_authorized(const std::string &ap_iface, const Tins::HWAddress<6> &mac, const std::optional<std::string> &netns);
// Set up hardware ACK mechanism: active monitor if prefer_active + cache allows, else start_ap.
// Returns true if active monitor was used (no AP VIF created).
bool setup_ack_iface(RunStatus &rs, const ActorPtr &actor, const Tins::HWAddress<6> &mac,
	const Channel &channel, bool prefer_active,
	const std::string &ap_iface, const Tins::Dot11Beacon &beacon);
// clears APSD/U-APSD bits for disabling sleep mode
// (Beacon, ProbeResp)
template<typename MgmtFrame>
void patch_apsd(MgmtFrame &frame) {
	frame.capabilities().apsd(false);
	for (auto &opt : frame.options()) {
		const size_t len = opt.data_size();
		// QoS Capability IE (0x2E): QoS Info byte, bits 0-3 = per-AC U-APSD flags
		if (opt.option() == Tins::Dot11::QOS_CAPABILITY && len >= 1) {
			const_cast<uint8_t *>(opt.data_ptr())[0] &= static_cast<uint8_t>(~dot11::QOS_INFO_UAPSD_AC_MASK);
		}
		// WME Parameter IE (AP->STA, subtype 0x01): QoS Info at data[6], bit 7 = U-APSD
		else if (opt.option() == Tins::Dot11::VENDOR_SPECIFIC && len >= dot11::WME_MIN_LEN) {
			const uint8_t *d = opt.data_ptr();
			if (std::equal(dot11::WME_OUI_TYPE.begin(), dot11::WME_OUI_TYPE.end(), d) &&
				d[4] == dot11::WME_SUBTYPE_PARAM) {
				const_cast<uint8_t *>(d)[dot11::WME_QOS_INFO_OFF] &=
					static_cast<uint8_t>(~(dot11::QOS_INFO_UAPSD_AC_MASK | 0x80u));
			}
		}
	}
}
void rewrite_ssid_in_frame(frame_raw_t &raw, const std::string &new_ssid);
void rewrite_bssid_in_frame(frame_raw_t &raw, const Tins::HWAddress<6> &bssid);
void strip_pmkid_from_rsn_ie(frame_raw_t &raw);
// strip all power-management capabilities from a raw Assoc{Req,Resp}
// - Capability Info APSD bit, QoS Capability IE, WME Info/Param IE  (U-APSD)
// - TSPEC IE                                                          (S-APSD)
// - Extended Capabilities IE bit 17                                   (WNM Sleep)
// - HE Capabilities Extended IE TWT Requester/Responder bits          (TWT)
void strip_power_mgmt_caps(frame_raw_t &raw);
}