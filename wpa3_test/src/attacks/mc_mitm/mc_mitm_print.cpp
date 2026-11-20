#include "attacks/mc_mitm/mc_mitm.h"
#include <tins/tins.h>
#include <utility>
#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "logger/log.h"
#include "net_parser/dot11_defs.h"
#include "net_parser/eap_defs.h"
#include "net_parser/radiotap_defs.h"
#include "system/hw_capabilities.h"
namespace wpa3_tester {
using namespace std;
using namespace chrono;
using namespace Tins;
static uint16_t get_seq_num(const Dot11 &frame) {
	if(const auto *mgmt = frame.find_pdu<Dot11ManagementFrame>()) return mgmt->seq_num();
	if(const auto *data = frame.find_pdu<Dot11Data>()) return data->seq_num();
	return 0;
}
string McMitm::frame_to_str(const Dot11 &frame) {
	const uint8_t type = frame.type();
	const uint8_t sub  = frame.subtype();
	const auto name = dot11::to_string(type, sub);
	if(name[0] != '<') {
		auto s = string(name);
		if(type != dot11::TYPE_CTRL) s += "(seq=" + to_string(get_seq_num(frame)) + ")";
		return s;
	}
	return "Frame(type=" + to_string(type) + ",sub=" + to_string(sub) + ")";
}
//TODO  add possibility to use log map (mac-> actor names)
void McMitm::print_rx(const LogLevel level, const string &prefix, const Dot11 &frame, const string &suffix) {
	if(frame.type() == Dot11::CONTROL) return;
	HWAddress<6> addr2;
	if(const auto *mgmt = frame.find_pdu<Dot11ManagementFrame>()) {
		addr2 = mgmt->addr2();
	} else if(const auto *data = frame.find_pdu<Dot11Data>()) {
		addr2 = data->addr2();
	} else if(frame.type() == Dot11::MANAGEMENT) {
		const auto raw = const_cast<Dot11 &>(frame).serialize();
		if(raw.size() >= dot11::ADDR2_END) addr2 = HWAddress<6>(raw.data() + dot11::ADDR2_OFFSET);
	}
	string msg = prefix + ": " + addr2.to_string() + " -> " + frame.addr1().to_string() + ": " + frame_to_str(frame);
	if(!suffix.empty()) msg += suffix;
	log(level, msg);
}
//TODO keep parsing again?
void McMitm::display_traffic(const frame_raw_t &raw, const string &prefix, const string &suffix) {
	const uint16_t rt_len = radiotap::get_rt_len(raw);
	const size_t hdr = (rt_len >= sizeof(ieee80211_radiotap_header) && raw.size() >= rt_len
	                    && raw[0] == PKTHDR_RADIOTAP_VERSION) ? rt_len : 0;
	if(hdr + dot11::MGMT_HDR_SIZE > raw.size()) return;
	const uint8_t fc0  = raw[hdr + dot11::FC_OFFSET];
	const uint8_t type = (fc0 >> dot11::FC_TYPE_SHIFT) & dot11::FC_TYPE_MASK;
	const uint8_t sub  = (fc0 >> dot11::FC_SUBTYPE_SHIFT) & dot11::FC_SUBTYPE_MASK;
	if(type == dot11::TYPE_CTRL) return;
	const HWAddress<6> addr1(raw.data() + hdr + dot11::ADDR1_OFFSET);
	const HWAddress<6> addr2(raw.data() + hdr + dot11::ADDR2_OFFSET);
	const bool is_null = type == dot11::TYPE_DATA
	    && (sub == dot11::DATA_NULL || sub == dot11::QOS_NULL);
	static constexpr uint8_t snap_eapol[] = { eap::ETHERTYPE_EAPOL_HI, eap::ETHERTYPE_EAPOL_LO };
	const bool eapol = std::ranges::search(raw, snap_eapol).begin() != raw.end();
	const EapolMsg eapol_msg = eapol ? get_eapol_msg_num(raw) : EapolMsg::Unknown;
	const auto level = eapol || (type == dot11::TYPE_DATA && !is_null) ? LogLevel::INFO : LogLevel::DEBUG;
	string eap;
	if(eapol) {
		const auto it = eapol_msg_labels.find(eapol_msg);
		eap = " [" + (it != eapol_msg_labels.end() ? string(it->second) : "EAPOL") + "]";
	}
	// SeqCtl: 16-bit LE, bits 15:4 = sequence number
	const uint16_t seqctl = static_cast<uint16_t>(raw[hdr + dot11::SEQCTL_OFFSET])
	                      | (static_cast<uint16_t>(raw[hdr + dot11::SEQCTL_OFFSET + 1]) << 8);
	const uint16_t seq = seqctl >> dot11::SEQCTL_SEQ_SHIFT;
	const auto name = dot11::to_string(type, sub);
	const string frame_str = name[0] != '<'
	    ? string(name) + "(seq=" + to_string(seq) + ")"
	    : "Frame(type=" + to_string(type) + ",sub=" + to_string(sub) + ")";
	log(level, prefix + ": " + addr2.to_string() + " -> " + addr1.to_string() + ": " + frame_str + eap + suffix);
}
void McMitm::display_traffic(const PDU &pdu, const string &prefix, const string &suffix) {
	const auto *dot11 = pdu.find_pdu<Dot11>();
	if(!dot11) return;
	const auto *data = pdu.find_pdu<Dot11Data>();
	const bool is_null = data && (data->subtype() == Dot11::DATA_NULL || data->subtype() == Dot11::QOS_DATA_NULL);
	const bool eapol = is_eapol(pdu);
	const auto level = eapol || (dot11->type() == Dot11::DATA && !is_null) ? LogLevel::INFO : LogLevel::DEBUG;
	string eap;
	if(eapol) {
		const auto raw = const_cast<PDU &>(pdu).serialize();
		const auto it = eapol_msg_labels.find(get_eapol_msg_num(raw));
		eap = it != eapol_msg_labels.end()
			? " [" + string(it->second) + "]"
			: " [" + eap_description(pdu) + "]";
	}
	print_rx(level, prefix, *dot11, eap + suffix);
}
}