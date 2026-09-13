#pragma once

#include "attacks/mc_mitm/mc_mitm.h"
#include "config/Actor_Config/Actor_Config_internal.h"
#include "pcap_helper.h"

namespace wpa3_tester {

// minimal McMitm fixture
constexpr auto AP_MAC = "11:22:33:44:55:66";
constexpr auto CLIENT_MAC = "aa:bb:cc:dd:ee:ff";

class McMitmTestable: public McMitm {
public:
	using McMitm::McMitm;
	mutable int real_send_count = 0;
	mutable int rogue_send_count = 0;

	mutable std::vector<std::vector<uint8_t>> real_sent_frames;
	mutable std::vector<std::vector<uint8_t>> rogue_sent_frames;

	std::string real_pcap_path = "/tmp/mc_mitm_.pcap";
	std::string rogue_pcap_path = "/tmp/mc_mitm_test_rogue.pcap";

	void set_ap_mac(const Tins::HWAddress<6> &mac) const { ap->set(SK::mac, mac.to_string()); }

	void send_to_real(Tins::PDU &pdu) const override;
	void send_to_real(const std::vector<uint8_t> &raw) const override;
	void send_to_rogue(Tins::PDU &pdu) const override;
	void send_to_rogue(const std::vector<uint8_t> &raw) const override;
private:
	// rewrites the entire file each time - guarantees no stale data across test cases
	void append_to_pcap(const std::string &path) const;
};

inline void McMitmTestable::send_to_real(Tins::PDU &pdu) const {
	++real_send_count;
	const auto raw = pdu.serialize();
	real_sent_frames.emplace_back(raw.begin(), raw.end());
	append_to_pcap(real_pcap_path);
}
inline void McMitmTestable::send_to_real(const std::vector<uint8_t> &raw) const {
	++real_send_count;
	real_sent_frames.push_back(raw);
	append_to_pcap(real_pcap_path);
}
inline void McMitmTestable::send_to_rogue(Tins::PDU &pdu) const {
	++rogue_send_count;
	const auto raw = pdu.serialize();
	rogue_sent_frames.emplace_back(raw.begin(), raw.end());
	append_to_pcap(rogue_pcap_path);
}
inline void McMitmTestable::send_to_rogue(const std::vector<uint8_t> &raw) const {
	++rogue_send_count;
	rogue_sent_frames.push_back(raw);
	append_to_pcap(rogue_pcap_path);
}
inline void McMitmTestable::append_to_pcap(const std::string &path) const {
	// collect the right frame list for this path
	const auto &frames = (path == real_pcap_path) ? real_sent_frames : rogue_sent_frames;
	pcap_t *dead = pcap_open_dead(DLT_IEEE802_11_RADIO, 65535);
	if(!dead) return;

	pcap_dumper_t *dumper = pcap_dump_open(dead, path.c_str()); // truncates if exists
	if(!dumper) {
		pcap_close(dead);
		return;
	}

	for(const auto &f: frames) {
		pcap_pkthdr hdr{};
		hdr.caplen = hdr.len = static_cast<uint32_t>(f.size());
		pcap_dump(reinterpret_cast<u_char *>(dumper), &hdr, f.data());
	}

	pcap_dump_close(dumper);
	pcap_close(dead);
}

inline std::unique_ptr<McMitmTestable> make_fixture() {
	auto r_sta_actor = ActorPtr(std::make_shared<Actor_Config_internal>());
	auto r_ap_actor = ActorPtr(std::make_shared<Actor_Config_internal>());
	auto sta_actor = ActorPtr(std::make_shared<Actor_Config_internal>());
	auto ap_actor = ActorPtr(std::make_shared<Actor_Config_internal>());

	r_sta_actor->set(SK::iface, "wlan1");
	r_ap_actor->set(SK::iface, "wlan2");
	sta_actor->set(SK::mac, std::string(CLIENT_MAC));
	ap_actor->set(SK::mac, std::string(AP_MAC));
	ap_actor->set(SK::ssid, std::string("test_mc_mitm"));

	auto m = std::make_unique<McMitmTestable>(r_sta_actor, r_ap_actor, sta_actor, ap_actor);
	m->client_state.update_state(ClientState::GotMitm);
	return m;
}
}