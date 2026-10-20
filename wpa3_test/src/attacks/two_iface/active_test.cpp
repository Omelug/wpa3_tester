#include "attacks/two_iface/active_test.h"
#include <atomic>
#include <chrono>
#include <fstream>
#include <thread>
#include <nlohmann/json.hpp>
#include <tins/tins.h>

#include "config/Actor_Config/actor_keys.h"
#include "config/RunStatus.h"
#include "default.h"
#include "interrupt.h"
#include "system/hw_capabilities.h"
#include "system/netlink_guards.h"
#include "system/utils.h"

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

	auto &actor_tx = rs.get_actor("transceiver");
	auto &actor_rx = rs.get_actor("receiver");

	const auto netns1 = actor_tx[SK::netns];
	const HWAddress<6> tx_mac(actor_tx.get(SK::mac));

	// Sniff ACK frames on the transceiver interface
	atomic ack_count{0};
	atomic stop{false};

	SnifferConfiguration sniff_cfg;
	sniff_cfg.set_promisc_mode(true);
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
	RadioTap rt;
	Dot11Data frame(actor_rx.get(SK::mac), tx_mac);
	frame.addr3(tx_mac); // BSSID
	frame.subtype(4);    // null data
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

	const json result = {{"acked", acked}, {"not_acked", not_acked}, {"success", acked >= burst * ack_threshold_pct / 100},};

	rs.save_result(result);
}
}
