#include "attacks/mc_mitm/wifi_util.h"
#include "net_parser/dot11_defs.h"
#include "net_parser/eap_defs.h"
#include "net_parser/radiotap_defs.h"
#include <fstream>
#include <iomanip>
#include <linux/nl80211.h>
#include <net/if.h>
#include <netlink/genl/ctrl.h>
#include <netlink/netlink.h>
#include <sstream>
#include "attacks/two_iface/TwoIfaceActive.h"
#include "config/Actor_Config/actor_keys.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "interrupt.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "system/netlink_guards.h"
#include "system/netlink_helper.h"
using namespace std;
using namespace Tins;
namespace wpa3_tester {
string get_ssid(const Dot11Beacon &beacon) {
	const auto opt = beacon.search_option(Dot11::SSID);
	if(!opt) return "";
	return { opt->data_ptr(), opt->data_ptr() + opt->data_size() };
}
Dot11Addrs get_addrs(const PDU &pdu, const frame_raw_t &raw) {
	const auto *dot11 = pdu.find_pdu<Dot11>();
	if(!dot11) return {};
	HWAddress<6> addr1 = dot11->addr1();
	HWAddress<6> addr2;
	if(const auto *mgmt = pdu.find_pdu<Dot11ManagementFrame>()) {
		addr2 = mgmt->addr2();
	} else if(const auto *data = pdu.find_pdu<Dot11Data>()) {
		addr2 = data->addr2();
	} else if(pdu.find_pdu<Dot11Control>()) {
		return { addr1, HWAddress<6>() };
	}
	// fallback addresses from raw (libtins cant parse some encrypted frames)
	if(addr2 == HWAddress<6>()) {
		const uint16_t rt_len = radiotap::get_rt_len(raw);
		if(rt_len && raw.size() >= static_cast<size_t>(rt_len) + dot11::ADDR2_END) {
			addr1 = HWAddress<6>(raw.data() + rt_len + dot11::ADDR1_OFFSET);
			addr2 = HWAddress<6>(raw.data() + rt_len + dot11::ADDR2_OFFSET);
		}
	}
	return { addr1, addr2 };
}
Dot11ProbeResponse beacon_to_probe_resp(const Dot11Beacon &beacon, const Channel &rogue_channel) {
	auto resp = Dot11ProbeResponse();
	resp.addr2(beacon.addr2());
	resp.addr3(beacon.addr3());
	resp.timestamp(0xAAAAAAAAAAAAAAAAULL);
	resp.interval(beacon.interval());
	resp.capabilities() = beacon.capabilities();
	for(const auto &opt: beacon.options()) {
		if(opt.option() == Dot11::TIM) continue; // remove, not in probe responses
		if(opt.option() == Dot11::DS_SET) {
			uint8_t ch = rogue_channel.ch_num;
			resp.add_option({ Dot11::DS_SET, 1, &ch });
			continue;
		}
		//FIXME in python is HT_OPERATION unchanged
		if(opt.option() == Dot11::HT_OPERATION && opt.data_size() >= 1) {
			vector ht_data(opt.data_ptr(), opt.data_ptr() + opt.data_size());
			ht_data[0] = static_cast<uint8_t>(rogue_channel.ch_num);
			resp.add_option({ Dot11::HT_OPERATION, ht_data.size(), ht_data.data() });
			continue;
		}
		resp.add_option(opt);
	}
	return resp;
}
bool is_eapol(const PDU &pdu) {
	const auto snap = pdu.find_pdu<SNAP>();
	if(snap && snap->eth_type() == eap::ETHERTYPE_EAPOL) return true;
	return pdu.find_pdu<EAPOL>() != nullptr;
}
EapolMsg get_eapol_msg_num(const frame_raw_t &raw, const bool print) {
	static constexpr uint8_t snap_eapol[] = { eap::ETHERTYPE_EAPOL_HI, eap::ETHERTYPE_EAPOL_LO };
	const auto it = std::ranges::search(raw, snap_eapol).begin();
	if(it == raw.end()) return EapolMsg::Unknown;
	const size_t off = static_cast<size_t>(it - raw.begin()) + 2;
	if(off + eap::EAPOL_KEY_MIN_SIZE > raw.size()) return EapolMsg::Unknown;
	if(raw[off + eap::EAPOL_KEY_OFF_TYPE] != eap::EAPOL_KEY) return EapolMsg::Unknown;
	const uint8_t ki_hi = raw[off + eap::EAPOL_KEY_OFF_KI_HI];
	const uint8_t ki_lo = raw[off + eap::EAPOL_KEY_OFF_KI_LO];
	const bool key_type = ki_lo & eap::KI_LO_TYPE;
	const bool key_ack  = ki_lo & eap::KI_LO_ACK;
	const bool install  = ki_lo & eap::KI_LO_INSTALL;
	const bool key_mic  = ki_hi & eap::KI_HI_MIC;
	const bool secure   = ki_hi & eap::KI_HI_SECURE;
	if(print) {
		log(LogLevel::DEBUG,
			"EAPOL key_info bits: type={} mic={} ack={} install={} secure={}",
			key_type, key_mic, key_ack, install, secure);
	}
	if(!key_type) {
		log(LogLevel::DEBUG, "EAPOL: Group Key Handshake frame");
		return EapolMsg::Group;
	}
	if(!key_mic && key_ack && !install && !secure) return EapolMsg::Msg1;
	if(key_mic && !key_ack && !install && !secure) return EapolMsg::Msg2;
	if(key_mic && key_ack && install && secure)    return EapolMsg::Msg3;
	// NOLINTNEXTLINE(clang-diagnostic-tautological-overlap-compare)
	if(key_mic && !key_ack && !install && secure)  return EapolMsg::Msg4;
	return EapolMsg::Unknown;
}
string eap_description(const PDU &pdu) {
	using namespace eap;
	const auto *eapol = pdu.find_pdu<EAPOL>();
	if(!eapol) return "EAPOL?";
	const auto raw = const_cast<EAPOL *>(eapol)->serialize();
	if(raw.size() < 2 || raw[1] != EAPOL_EAP) return "EAPOL type=" + std::to_string(raw[1]);
	if(raw.size() <= EAP_CODE_OFF) return "EAP";
	const auto code = static_cast<EapCode>(raw[EAP_CODE_OFF]);
	if(code == CODE_SUCCESS || code == CODE_FAILURE) return "EAP " + string(to_string(code));
	if(code == CODE_REQUEST || code == CODE_RESPONSE) {
		if(raw.size() <= EAP_TYPE_OFF) return "EAP " + string(to_string(code));
		return "EAP " + string(to_string(code)) + " " + string(to_string(static_cast<EapType>(raw[EAP_TYPE_OFF])));
	}
	return "EAP code=" + std::to_string(raw[EAP_CODE_OFF]);
}
vector<uint8_t> ensure_radiotap(const frame_raw_t &raw) {
	if(raw.size() < sizeof(ieee80211_radiotap_header))
		throw run_err("ensure_radiotap: frame too short ({} bytes)", raw.size());
	const uint16_t rt_len = radiotap::get_rt_len(raw);
	if(raw[0] == PKTHDR_RADIOTAP_VERSION && rt_len >= sizeof(ieee80211_radiotap_header) && raw.size() >= rt_len)
		return raw;
	if(((raw[0] >> dot11::FC_TYPE_SHIFT) & dot11::FC_TYPE_MASK) > dot11::TYPE_DATA)
		throw run_err("ensure_radiotap: not a valid 802.11 frame, FC=0x{:02x}", raw[0]);
	vector<uint8_t> result;
	result.reserve(radiotap::MINIMAL_INJECT_HDR.size() + raw.size());
	result.insert(result.end(), radiotap::MINIMAL_INJECT_HDR.begin(), radiotap::MINIMAL_INJECT_HDR.end());
	result.insert(result.end(), raw.begin(), raw.end());
	return result;
}
Dot11Beacon append_csa(const Dot11Beacon &beacon, const Channel &new_channel, const uint8_t count) {
	Dot11Beacon copy = beacon;
	copy.channel_switch({ 1, //type
		new_channel.ch_num,
		count });
	return copy;
}
void start_ap(RunStatus &rs, const string &ap_iface, const ActorPtr &base_actor, const Channel &channel,
	const Dot11Beacon &beacon, optional<HWAddress<6>> mac, int interval, int dtim_period) {
	// in order of priority: provided ssid, ssid from beacon, or default
	const auto *ssid_ie = beacon.search_option(Dot11ManagementFrame::SSID);
	if(!ssid_ie || ssid_ie->data_size() <= 0) throw run_err("invalid beacon for start ap");
	auto ap_ssid = string(reinterpret_cast<const char *>(ssid_ie->data_ptr()), ssid_ie->data_size());
	const optional<string> &netns = base_actor[SK::netns];
	// split beacon into head (before TIM) and tail (after TIM)
	const auto bssid = mac.has_value() ? HWAddress(*mac) : beacon.addr2();
	Dot11Beacon head(beacon.addr1(), bssid);
	head.addr3(bssid);
	head.interval(beacon.interval());
	head.capabilities() = beacon.capabilities();
	vector<uint8_t> tail_bytes;
	bool past_tim = false;
	for(const auto &opt: beacon.options()) {
		if(opt.option() == Dot11ManagementFrame::TIM) {
			past_tim = true;
			continue;
		}
		if(!past_tim) {
			head.add_option(opt);
		} else {
			// Serialize tail IEs manually
			tail_bytes.push_back(opt.option());
			tail_bytes.push_back(static_cast<uint8_t>(opt.data_size()));
			tail_bytes.insert(tail_bytes.end(), opt.data_ptr(), opt.data_ptr() + opt.data_size());
		}
	}
	// Serialize head to hex
	const auto head_bytes = head.serialize();
	ostringstream head_hex;
	for(const auto b: head_bytes) head_hex << hex << setw(2) << setfill('0') << static_cast<int>(b);
	//TODO some drivers drop kernel if  const optional<string>& ssid = nullopt, up during subiface cchange to __ap ?  - maybe only ath_htc/mt7 ?
	//(weird af but I will not debug it if I need restart notebook fortail_bytes run)
	netlink_helper::NetlinkRegistry::get_fd(netns);
	base_actor->set_iface_down();
	base_actor->set_wifi_type(NL80211_IFTYPE_MONITOR, {}); //FIXME duplicate?
	// add AP virtual interface
	hw_capabilities::run_cmd(
		{ "iw", "dev", base_actor.get(SK::iface), "interface", "add", ap_iface, "type", "managed" }, netns, true);
	if(netlink_helper::wait_for_iface_appear(ap_iface, netns)) throw setup_err("Interface {} did not appear", ap_iface);
	interruptible_sleep(2000ms); //FIXME not nice , but stable
	hw_capabilities::set_iface_down(ap_iface, netns);
	hw_capabilities::set_wifi_type(ap_iface, NL80211_IFTYPE_AP, netns);
	if(mac.has_value()) hw_capabilities::set_mac_address(ap_iface, mac.value(), netns);
	hw_capabilities::set_iface_up(ap_iface, netns);
	base_actor->set_iface_up();
	// start ap command
	vector<string> cmd = { "iw",
		"dev",
		ap_iface,
		"ap",
		"start",
		ap_ssid,
		to_string(hw_capabilities::channel_to_freq(channel)),
		to_string(interval),
		to_string(dtim_period),
		"head",
		head_hex.str() };
	if(!tail_bytes.empty()) {
		ostringstream tail_hex;
		for(const auto b: tail_bytes) tail_hex << hex << setw(2) << setfill('0') << static_cast<int>(b);
		cmd.emplace_back("tail");
		cmd.push_back(tail_hex.str());
	}
	if(netns.has_value()) cmd.insert(cmd.begin(), { "ip", "netns", "exec", *netns });
	interruptible_sleep(chrono::milliseconds(200)); // firmware need some time to up ? //TODO hardcoded
	rs.process_manager.run(ap_iface + "_start", cmd);
	// With rt2800usb we need "ifconfig up" after "ap start" to make the interface //TODO rewritten from python, try
	// acknowledge received frames and send ACKs
	//interruptible_sleep(chrono::milliseconds(100));
	base_actor->set_iface_up();
	hw_capabilities::set_iface_up(ap_iface, netns);
	//hw_capabilities::run_cmd({"iw", "dev", ap_iface, "set", "power_save", "off"}, netns); //TODO disable for test ?
}
void start_ap_hostapd(RunStatus &rs, const string &ap_iface, const ActorPtr &base_actor, const Channel &channel, optional<HWAddress<6>> bssid) {
	if(ap_iface.size() >= IFNAMSIZ)
		throw std::runtime_error("start_ap_hostapd: iface name '" + ap_iface + "' is " +
			std::to_string(ap_iface.size()) + " chars, exceeds IFNAMSIZ-1=" + std::to_string(IFNAMSIZ - 1));
	const optional<string> &netns = base_actor[SK::netns];
	netlink_helper::NetlinkRegistry::get_fd(netns);
	base_actor->set_iface_down();
	base_actor->set_wifi_type(NL80211_IFTYPE_MONITOR, {});
	hw_capabilities::run_cmd(
		{ "iw", "dev", base_actor.get(SK::iface), "interface", "add", ap_iface, "type", "managed" }, netns);
	if(netlink_helper::wait_for_iface_appear(ap_iface, netns))
		throw setup_err("Interface " + ap_iface + " did not appear");
	interruptible_sleep(2s); //TODO hardcoded timeout
	// Leave VIF in managed+down state - hostapd sets the mode and brings it up itself
	hw_capabilities::set_iface_down(ap_iface, netns);
	base_actor->set_iface_up();
	const string hw_mode = channel.ch_num <= 14 ? "g" : "a"; //TODO no for 6GHZ
	const auto conf = rs.run_folder() / ("hostapd_" + ap_iface + ".conf");
	{
		ofstream f(conf);
		f << "interface=" << ap_iface << "\n"
		  << "ssid=start_ap_hostapd\n"
		  << "channel=" << static_cast<int>(channel.ch_num) << "\n"
		  << "hw_mode=" << hw_mode << "\n";
		if(bssid) f << "bssid=" << bssid->to_string() << "\n";
	}
	set_public_perms(conf);
	vector<string> cmd;
	if(netns) cmd.insert(cmd.end(), { "ip", "netns", "exec", netns.value() });
	cmd.insert(cmd.end(), { hostapd::get_hostapd("2_9"), conf.string(), "-d" });
	rs.process_manager.run(ap_iface + "_hostapd", cmd, rs.run_folder());
	rs.process_manager.wait_for(ap_iface + "_hostapd", "AP-ENABLED", chrono::seconds(20));
}
void stop_ap(const string &iface, const optional<string> &netns) {
	log(LogLevel::INFO, "Stopping AP: iw dev {} del", iface);
	hw_capabilities::run_cmd({ "iw", "dev", iface, "del" }, netns, true);
}
bool setup_ack_iface(RunStatus &rs, const ActorPtr &actor, const HWAddress<6> &mac,
	const Channel &channel, const bool prefer_active,
	const string &ap_iface, const Dot11Beacon &beacon) {
	if(prefer_active) {
		if(const auto needs_active = TwoIfaceActive::find_cache_needs_active(actor)) {
			if(*needs_active) actor->set(BK::active_monitor, true);
			else log(LogLevel::INFO, "prefer_active: active monitor works without active_monitor hw flag");
			// mode change first; some drivers reset MAC on type switch so set MAC after
			actor->set_monitor_mode(true);
			actor->set_mac_address(mac);
			actor->set_iface_up();
			actor->set_channel(channel);
			return true;
		}
		log(LogLevel::WARNING, "prefer_active: no cache for {}, using AP VIF fallback", actor.get(SK::iface));
	}
	actor->set_mac_address(mac);
	//TODO popsat v pdf
	// strip RSN IE so this ack-only VIF runs as open AP - prevents mac80211 from applying
	// dot11RSNAConfigSATimeout (30s deauth) when no PTK is ever installed via this VIF
	Dot11Beacon open_beacon = beacon;
	open_beacon.remove_option(Dot11ManagementFrame::RSN);
	start_ap(rs, ap_iface, actor, channel, open_beacon, mac);
	return false;
}
// Returns the byte offset of the first IE in a raw management frame (past radiotap + 802.11 header + fixed fields).
// Returns raw.size() on error (frame too short or unrecognised).
static size_t mgmt_ie_start(const frame_raw_t &raw) {
	const uint16_t rt_len = radiotap::get_rt_len(raw);
	const size_t hdr = (rt_len >= sizeof(ieee80211_radiotap_header) && raw.size() >= rt_len && raw[0] == PKTHDR_RADIOTAP_VERSION) ? rt_len : 0;
	if(hdr >= raw.size()) return raw.size();
	const uint8_t sub = (raw[hdr] >> dot11::FC_SUBTYPE_SHIFT) & dot11::FC_SUBTYPE_MASK;
	const size_t fixed =
		(sub == dot11::MGMT_REASSOC_REQ)                                        ? dot11::REASSOC_REQ_FIXED :
		(sub == dot11::MGMT_PROBE_RESP || sub == dot11::MGMT_BEACON)            ? dot11::BEACON_FIXED      :
		(sub == dot11::MGMT_ASSOC_RESP || sub == dot11::MGMT_REASSOC_RESP)      ? dot11::ASSOC_RESP_FIXED  :
			dot11::ASSOC_REQ_FIXED;
	return hdr + dot11::MGMT_HDR_SIZE + fixed;
}
void patch_ht_operation_in_frame(frame_raw_t &raw, const uint8_t channel) {
	const size_t ie_start = mgmt_ie_start(raw);
	for(size_t i = ie_start; i + 1 < raw.size();) {
		const uint8_t ie_len = raw[i + 1];
		if(i + dot11::IE_HDR_SIZE + ie_len > raw.size()) break;
		if(raw[i] == dot11::IE_HT_OPERATION && ie_len >= 1) {
			raw[i + dot11::IE_HDR_SIZE] = channel;
			return;
		}
		i += dot11::IE_HDR_SIZE + ie_len;
	}
}
void rewrite_ssid_in_frame(frame_raw_t &raw, const string &new_ssid) {
	const size_t ie_start = mgmt_ie_start(raw);
	if(raw.size() < ie_start + dot11::IE_HDR_SIZE) return;
	for(size_t i = ie_start; i + 1 < raw.size();) {
		if(raw[i] == dot11::IE_SSID) {
			const size_t old_len = raw[i + 1];
			const size_t new_len = min(new_ssid.size(), static_cast<size_t>(dot11::SSID_MAX_LEN));
			const auto it = raw.begin() + static_cast<ptrdiff_t>(i + dot11::IE_HDR_SIZE);
			raw.erase(it, it + static_cast<ptrdiff_t>(old_len));
			raw.insert(raw.begin() + static_cast<ptrdiff_t>(i + dot11::IE_HDR_SIZE),
				reinterpret_cast<const uint8_t *>(new_ssid.data()),
				reinterpret_cast<const uint8_t *>(new_ssid.data()) + new_len);
			raw[i + 1] = static_cast<uint8_t>(new_len);
			return;
		}
		const size_t step = dot11::IE_HDR_SIZE + raw[i + 1];
		if(i + step > raw.size()) break; // malformed IE: claimed length exceeds frame
		i += step;
	}
}
// Strip PMKID list from RSN IE in a raw management frame.
// Zeroes PMKID Count and removes the 16-byte entries; fixes IE length field.
void strip_pmkid_from_rsn_ie(frame_raw_t &raw) {
	const size_t ie_start = mgmt_ie_start(raw);
	if(raw.size() < ie_start + dot11::IE_HDR_SIZE) return;
	for(size_t i = ie_start; i + 1 < raw.size();) {
		const uint8_t ie_len = raw[i + 1];
		if(i + dot11::IE_HDR_SIZE + ie_len > raw.size()) break;
		if(raw[i] == dot11::IE_RSN) {
			// version+group+pw_count+pw(4n)+akm_count+akm(4n)+caps+pmkid_count
			size_t off = dot11::RSN_VERSION_SIZE + dot11::RSN_GROUP_SIZE;
			if(off + dot11::RSN_COUNT_SIZE > ie_len) return;
			off += dot11::RSN_COUNT_SIZE + (static_cast<uint16_t>(raw[i+dot11::IE_HDR_SIZE+off]) |
			       (static_cast<uint16_t>(raw[i+dot11::IE_HDR_SIZE+off+1]) << 8)) * dot11::RSN_SUITE_SIZE;
			if(off + dot11::RSN_COUNT_SIZE > ie_len) return;
			off += dot11::RSN_COUNT_SIZE + (static_cast<uint16_t>(raw[i+dot11::IE_HDR_SIZE+off]) |
			       (static_cast<uint16_t>(raw[i+dot11::IE_HDR_SIZE+off+1]) << 8)) * dot11::RSN_SUITE_SIZE;
			off += dot11::RSN_CAPS_SIZE;
			if(off + dot11::RSN_COUNT_SIZE > ie_len) return;
			const uint16_t pmkid_cnt = static_cast<uint16_t>(raw[i+dot11::IE_HDR_SIZE+off]) |
			                           static_cast<uint16_t>(raw[i + dot11::IE_HDR_SIZE + off + 1]) << 8;
			if(pmkid_cnt == 0) return;
			raw[i+dot11::IE_HDR_SIZE+off] = 0; raw[i+dot11::IE_HDR_SIZE+off+1] = 0;
			const size_t pmkid_bytes = pmkid_cnt * dot11::RSN_PMKID_SIZE;
			raw.erase(raw.begin() + static_cast<ptrdiff_t>(i+dot11::IE_HDR_SIZE+off+dot11::RSN_COUNT_SIZE),
			          raw.begin() + static_cast<ptrdiff_t>(i+dot11::IE_HDR_SIZE+off+dot11::RSN_COUNT_SIZE+pmkid_bytes));
			raw[i+1] = static_cast<uint8_t>(ie_len - pmkid_bytes);
			return;
		}
		i += dot11::IE_HDR_SIZE + ie_len;
	}
}
// strip all power-management capabilities from a raw Assoc{Req,Resp} frame
// works on both directions (STA->AP and AP->STA)
void strip_power_mgmt_caps(frame_raw_t &raw) {
	const uint16_t rt_len = radiotap::get_rt_len(raw);
	const size_t hdr = rt_len >= sizeof(ieee80211_radiotap_header) && raw.size() >= rt_len && raw[0] == PKTHDR_RADIOTAP_VERSION
		? rt_len : 0;
	// capability information is always the first fixed field in Assoc{Req,Resp} (2 bytes)
	const size_t cap_off = hdr + dot11::MGMT_HDR_SIZE;
	if(cap_off + sizeof(uint16_t) <= raw.size())
		raw[cap_off + 1] &= static_cast<uint8_t>(~static_cast<uint8_t>(dot11::CAP_APSD >> 8)); // clear APSD (B11)
	const size_t ie_start = mgmt_ie_start(raw);
	for(size_t i = ie_start; i + 1 < raw.size();) {
		const uint8_t ie_id  = raw[i];
		const uint8_t ie_len = raw[i + 1];
		if(i + dot11::IE_HDR_SIZE + ie_len > raw.size()) break;
		// S-APSD: remove TSPEC IE entirely
		if(ie_id == dot11::IE_TSPEC) {
			raw.erase(raw.begin() + static_cast<ptrdiff_t>(i),
			          raw.begin() + static_cast<ptrdiff_t>(i + dot11::IE_HDR_SIZE + ie_len));
			continue; // i unchanged - now points to next IE
		}
		// U-APSD: QoS Capability IE - clear per-AC U-APSD bits
		if(ie_id == dot11::IE_QOS_CAPABILITY && ie_len >= 1) {
			raw[i + dot11::IE_HDR_SIZE] &= static_cast<uint8_t>(~dot11::QOS_INFO_UAPSD_AC_MASK);
		}
		// U-APSD: WME Information (STA->AP, subtype 0x00) or Parameter (AP->STA, subtype 0x01) IE
		else if(ie_id == dot11::IE_VENDOR_SPECIFIC && ie_len >= dot11::WME_MIN_LEN) {
			const uint8_t *d = &raw[i + dot11::IE_HDR_SIZE];
			if(std::equal(dot11::WME_OUI_TYPE.begin(), dot11::WME_OUI_TYPE.end(), d) &&
			   (d[4] == dot11::WME_SUBTYPE_INFO || d[4] == dot11::WME_SUBTYPE_PARAM)) {
				raw[i + dot11::IE_HDR_SIZE + dot11::WME_QOS_INFO_OFF] &=
					static_cast<uint8_t>(~(dot11::QOS_INFO_UAPSD_AC_MASK | 0x80u));
			}
		}
		// WNM Sleep: clear bit 17 of Extended Capabilities IE
		else if(ie_id == dot11::IE_EXTENDED_CAPS && ie_len > dot11::EXTENDED_CAPS_WNM_SLEEP_BYTE) {
			raw[i + dot11::IE_HDR_SIZE + dot11::EXTENDED_CAPS_WNM_SLEEP_BYTE] &=
				static_cast<uint8_t>(~dot11::EXTENDED_CAPS_WNM_SLEEP_MASK);
		}
		// TWT: clear Requester/Responder bits in HE Capabilities Extended IE
		else if(ie_id == dot11::IE_EXT_TAG && ie_len >= 2 &&
		        raw[i + dot11::IE_HDR_SIZE] == static_cast<uint8_t>(dot11::IE_EXT_HE_CAPS)) {
			raw[i + dot11::IE_HDR_SIZE + 1] &=
				static_cast<uint8_t>(~(dot11::HE_MAC_TWT_REQUESTER | dot11::HE_MAC_TWT_RESPONDER));
		}
		i += dot11::IE_HDR_SIZE + ie_len;
	}
}
void rewrite_bssid_in_frame(frame_raw_t &raw, const HWAddress<6> &bssid) {
	const uint16_t rt_len = radiotap::get_rt_len(raw);
	const size_t hdr = (rt_len >= sizeof(ieee80211_radiotap_header) && raw.size() >= rt_len && raw[0] == PKTHDR_RADIOTAP_VERSION) ? rt_len : 0;
	if(hdr + dot11::ADDR3_END > raw.size()) return;
	ranges::copy(bssid, raw.begin() + static_cast<ptrdiff_t>(hdr + dot11::ADDR2_OFFSET));
	ranges::copy(bssid, raw.begin() + static_cast<ptrdiff_t>(hdr + dot11::ADDR3_OFFSET));
}
}