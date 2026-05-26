#include "attacks/two_iface/active_test.h"
#include <atomic>
#include <chrono>
#include <fstream>
#include <thread>
#include <nlohmann/json.hpp>
#include <tins/tins.h>
#include "config/actor_keys.h"
#include "config/RunStatus.h"
#include "system/hw_capabilities.h"
#include "system/netlink_guards.h"
#include "system/utils.h"

namespace wpa3_tester::active_test{
using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;
using nlohmann::json;

static constexpr int BURST = 50;

void run_attack(RunStatus &rs) {
	auto &actor_tx = rs.get_actor("transceiver");
	auto &actor_rx = rs.get_actor("receiver");

	const string iface1 = actor_tx.get(SK::iface);
	const string iface2 = actor_rx.get(SK::iface);
	const auto netns1 = actor_tx[SK::netns];

	const HWAddress<6> rx_mac(actor_rx.get(SK::mac));
	const HWAddress<6> tx_mac(actor_tx.get(SK::mac));

	// Sniff ACK frames on the transceiver interface
	atomic ack_count{0};
	atomic stop{false};

	SnifferConfiguration sniff_cfg;
	sniff_cfg.set_promisc_mode(true);
	sniff_cfg.set_immediate_mode(true);
	sniff_cfg.set_filter("wlan addr1 " + tx_mac.to_string());

	netlink_helper::NetNSContext ns(netns1);

	Sniffer sniffer(iface1, sniff_cfg);
	thread sniffer_thread([&] {
		sniffer.sniff_loop([&](PDU &pdu) -> bool {
			if (stop) return false;
			if (pdu.find_pdu<Dot11Ack>()) ++ack_count;
			return true;
		});
	});

	// Build a null data frame: transceiver -> receiver
	RadioTap rt;
	Dot11Data frame;
	frame.addr1(rx_mac); // destination
	frame.addr2(tx_mac); // source
	frame.addr3(tx_mac); // BSSID
	frame.subtype(4);    // null data
	rt /= frame;

	PacketSender sender(iface1);
	this_thread::sleep_for(milliseconds(200)); // let sniffer thread start

	for(int i = 0; i < BURST; ++i) {
		sender.send(rt);
		this_thread::sleep_for(milliseconds(10));
	}

	this_thread::sleep_for(milliseconds(200));
	stop = true;
	sniffer.stop_sniff();
	sniffer_thread.join();

	const int acked     = ack_count.load();
	const int not_acked = BURST - acked;

	const json result = {
		{"acked",     acked},
		{"not_acked", not_acked},
		{"success",   acked >= BURST * 95 / 100},
	};

	const path result_path = rs.run_folder() / "result.json";
	{
		ofstream ofs(result_path);
		ofs << result.dump(2);
	}
	set_public_perms(result_path);
}
}
