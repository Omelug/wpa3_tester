#include "attacks/two_iface/active_test.h"
#include <atomic>
#include <chrono>
#include <nlohmann/json.hpp>
#include <thread>
#include <tins/tins.h>
#include "attacks/two_iface/TwoIfaceActive.h"

#include "config/Actor_Config/actor_keys.h"
#include "config/RunStatus.h"
#include "net_parser/dot11_defs.h"
#include "config/global_config.h"
#include "interrupt.h"
#include "system/hw_capabilities.h"
#include "system/netlink_guards.h"

namespace wpa3_tester::active_test{
using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;
using nlohmann::json;

void run_attack(RunStatus &rs){
	const auto &att_cfg = rs.config().at("attack_config");
	const int burst             = att_cfg.at("burst").get<int>();
	const int frame_interval_ms = att_cfg.at("frame_interval_ms").get<int>();
	const int sleep_before_ms   = att_cfg.at("sleep_before_ms").get<int>();
	const int sleep_after_ms    = att_cfg.at("sleep_after_ms").get<int>();
	const int ack_threshold_pct = att_cfg.at("ack_threshold_pct").get<int>();
	const bool use_spoofed      = att_cfg.value("use_spoofed", false);

	auto &actor_tx = rs.get_actor("transceiver");
	auto &actor_rx = rs.get_actor("receiver");

	const auto netns1 = actor_tx[SK::netns];

	if(use_spoofed) {
		const HWAddress<6> spoof_tx("02:aa:aa:aa:aa:01");
		const HWAddress<6> spoof_rx("02:aa:aa:aa:aa:02");
		const auto ch_num = get_global_config().at("global_variables").at("default_channel_2_4").get<uint8_t>();
		const Channel ch{ch_num, WifiBand::BAND_2_4, nullopt};
		actor_tx->set_mac_address(spoof_tx);
		actor_tx->set_iface_up();
		actor_tx->set_channel(ch);
		actor_rx->set_mac_address(spoof_rx);
		actor_rx->set_iface_up();
		actor_rx->set_channel(ch);
	}
	const HWAddress<6> tx_mac(actor_tx.get(SK::mac));
	const HWAddress<6> rx_mac(actor_rx.get(SK::mac));

	// Sniff ACK frames on the transceiver interface
	atomic ack_count{0};
	atomic stop{false};

	SnifferConfiguration sniff_cfg;
	sniff_cfg.set_immediate_mode(true);
	sniff_cfg.set_filter("wlan addr1 " + tx_mac.to_string());

	netlink_helper::NetNSContext ns(netns1);

	Sniffer sniffer(actor_tx.get(SK::iface), sniff_cfg);
	thread sniffer_thread([&]{
		sniffer.sniff_loop([&](PDU &pdu) ->bool{
			if(stop) return false;
			if(pdu.find_pdu<Dot11Ack>()) ++ack_count;
			return true;
		});
	});

	// Build a null data frame: transceiver -> receiver
	RadioTap rt{};
	Dot11Data frame(rx_mac, tx_mac);
	frame.addr3(tx_mac); // BSSID
	frame.subtype(dot11::DATA_NULL);
	rt.inner_pdu(frame);

	PacketSender sender(actor_tx.get(SK::iface));
	interruptible_sleep(milliseconds(sleep_before_ms));

	for(int i = 0; i < burst; ++i){
		sender.send(rt);
		interruptible_sleep(milliseconds(frame_interval_ms));
	}

	interruptible_sleep(milliseconds(sleep_after_ms));
	stop = true;
	sniffer.stop_sniff();
	sniffer_thread.join();

	const int acked = ack_count.load();
	const int not_acked = burst - acked;

	const json result = {{"acked", acked}, {"not_acked", not_acked}, {"use_spoofed", use_spoofed},
		{"success", acked >= burst * ack_threshold_pct / 100},};

	rs.save_result(result);
	TwoIfaceActive::backfill_cache(rs.get_actor("transceiver"), rs.get_actor("receiver"), result);
}
}
