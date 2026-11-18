#include "attacks/mc_mitm/mc_mitm.h"

#include <tins/tins.h>
#include <utility>
#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "logger/log.h"
#include "net_parser/dot11_defs.h"
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

//TODO display traffci SAE
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

void McMitm::display_traffic(const frame_raw_t &raw, const string &prefix, const string &suffix) {
	const RadioTap rt(raw.data(), raw.size());
	const auto *dot11 = rt.find_pdu<Dot11>();
	if(!dot11) return;

	const auto *data = rt.find_pdu<Dot11Data>();
	const bool is_null = data && (data->subtype() == Dot11::DATA_NULL || data->subtype() == Dot11::QOS_DATA_NULL);
	const bool eapol = is_eapol(rt);

	const auto level = eapol || (dot11->type() == Dot11::DATA && !is_null) ? LogLevel::INFO : LogLevel::DEBUG;

	string eap;
	if(eapol) {
		const auto it = eapol_msg_labels.find(get_eapol_msg_num(raw));
		eap = it != eapol_msg_labels.end()
			? " [" + string(it->second) + "]"
			: " [" + eap_description(rt) + "]";
	}

	print_rx(level, prefix, *dot11, eap + suffix);
}

void McMitm::display_traffic(const PDU &pdu, const string &prefix, const string &suffix) {
	display_traffic(const_cast<PDU &>(pdu).serialize(), prefix, suffix);
}
}