#include "system/hw_capabilities.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <format>
#include <random>
#include <thread>
#include <vector>
#include <reproc++/drain.hpp>
#include <sys/wait.h>
#include <tins/tins.h>
#include "attacks/mc_mitm/MonitorSocket.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "config/global_config.h"
#include "config/RunStatus.h"
#include "logger/log.h"
#include "system/netlink_guards.h"
#include "system/netlink_helper.h"

namespace wpa3_tester{
using namespace std;
using namespace Tins;
using namespace filesystem;
using namespace chrono;

static vector<uint8_t> make_label(){
	static mt19937 rng{random_device{}()};
	uniform_int_distribution<uint32_t> dist;
	vector<uint8_t> label = {'A', 'A', 'A', 'A'};
	// two random uint32 big-endian (matches Python struct.pack(">II", ...))
	for(const uint32_t v: {dist(rng), dist(rng)}) for(int i = 3; i >= 0; i--) label.push_back((v >> (i * 8)) & 0xFF);
	return label;
}

vector<vector<uint8_t>> hw_capabilities::inject_and_capture(MonitorSocket &sout, MonitorSocket &sin, PDU &pdu,
															const int channel, const int count, const int retries
){
	const auto label = make_label();

	// Clone pdu and append label as Raw payload
	auto frame = unique_ptr<PDU>(pdu.clone());
	frame->inner_pdu(new RawPDU(label.data(), label.size()));

	const auto *d11 = pdu.find_pdu<Dot11>();
	const bool has_mf = d11 && d11->more_frag();

	vector<vector<uint8_t>> captured;
	int attempt = 0;

	while(true){
		sout.send(*frame, channel);

		// MF workaround: send a dummy frame after MF-flagged frame (Intel/RT5572 driver quirk)
		if(sout.mf_workaround && has_mf){
			if(const auto *qos = pdu.find_pdu<Dot11QoSData>()){
				Dot11QoSData fix;
				fix.qos_control(qos->qos_control() & 0x000F); // preserve TID
				sout.send(fix, channel);
			} else{
				Dot11Data fix;
				sout.send(fix, channel);
			}
		}

		// Capture for 1 second, filter frames containing the label
		const auto deadline = steady_clock::now() + seconds(1);
		while(steady_clock::now() < deadline){
			auto r = sin.recv();
			if(!r){
				this_thread::sleep_for(milliseconds(1));
				continue;
			}
			const auto it = ranges::search(r.raw, label).begin();
			if(it != r.raw.end()){
				captured.push_back(std::move(r.raw));
				if(count > 0 && static_cast<int>(captured.size()) >= count) break;
			}
		}

		if(!captured.empty() || attempt >= retries) break;
		attempt++;
	}

	return captured;
}

void hw_capabilities::flush_socket(MonitorSocket &s){
	for(int i = 0; i < 10000 && s.recv(); i++);
}

optional<pair<HWAddress<6>,string>> hw_capabilities::get_nearby_ap_addr(MonitorSocket &sin){
	struct Entry{
		int8_t rssi;
		HWAddress<6> mac;
		string ssid;
	};
	vector<Entry> beacons;
	const auto deadline = steady_clock::now() + milliseconds(500);
	while(steady_clock::now() < deadline){
		auto r = sin.recv();
		if(!r){
			this_thread::sleep_for(milliseconds(1));
			continue;
		}
		try{
			const RadioTap rt(r.raw.data(), r.raw.size());
			if(!(rt.present() & RadioTap::DBM_SIGNAL)) continue;
			const auto *beacon = rt.find_pdu<Dot11Beacon>();
			if(!beacon) continue;
			beacons.push_back({rt.dbm_signal(), beacon->addr2(), get_ssid(*beacon)});
		} catch(...){}
	}
	if(beacons.empty()) return nullopt;
	const auto best = ranges::max_element(beacons, [](const auto &a, const auto &b){ return a.rssi < b.rssi; });
	return pair{best->mac, best->ssid};
}

ProbeCapture hw_capabilities::capture_probe_response_ack(MonitorSocket &sout, MonitorSocket &sin, PDU &probe_req,
														const int channel, const int retries
){
	const auto [addr1, addr2] = get_addrs(probe_req, {});
	if(addr2 == HWAddress<6>()) return {};
	const auto src = addr2; // own mac
	const auto dst = addr1; // AP/peer

	ProbeCapture result;
	int attempt = 0;
	while(true){
		flush_socket(sin);
		sout.send(probe_req, channel);
		const auto deadline = steady_clock::now() + seconds(1);
		while(steady_clock::now() < deadline){
			auto r = sin.recv();
			if(!r){
				this_thread::sleep_for(milliseconds(1));
				continue;
			}
			try{
				const RadioTap rt(r.raw.data(), r.raw.size());
				const auto addrs = get_addrs(rt, r.raw);
				if(rt.find_pdu<Dot11ProbeResponse>()){
					if(addrs.addr1 == src && addrs.addr2 == dst) result.rx_probes.push_back(r.raw);
				} else if(rt.find_pdu<Dot11Ack>()){
					if(addrs.addr1 == dst) result.tx_acks.push_back(r.raw);
				}
			} catch(...){}
		}
		if((!result.rx_probes.empty() && !result.tx_acks.empty()) || attempt >= retries) break;
		log(LogLevel::INFO, " Unable to capture probe request, retrying.");
		attempt++;
	}
	return result;
}

int hw_capabilities::test_packet_injection(MonitorSocket &sout, MonitorSocket &sin, PDU &pdu,
											const function<bool(const vector<uint8_t> &)> &test_func,
											const string &frametype, const string &msgfail, const int channel
){
	const auto packets = inject_and_capture(sout, sin, pdu, channel, 1);
	if(packets.empty()){
		log(LogLevel::ERROR, "[-] Unable to capture injected {}.", frametype);
		return FLAG_NOCAPTURE;
	}
	if(!ranges::all_of(packets, test_func)){
		log(LogLevel::ERROR, "[-] {}", vformat(msgfail, make_format_args(frametype)));
		return FLAG_FAIL;
	}
	log(LogLevel::INFO, "    Properly captured injected {}.", frametype);
	return 0;
}

int hw_capabilities::test_injection_more_fragments(MonitorSocket &sout, MonitorSocket &sin, const Dot11Ref &ref,
													const string &strtype, const int channel
){
	log(LogLevel::INFO, "--- Testing injection of frame with more fragments flag using {}", strtype);

	Dot11QoSData p;
	p.addr1(ref.addr1);
	p.addr2(ref.addr2);
	if(ref.from_ds) p.from_ds(1);
	if(ref.to_ds) p.to_ds(1);
	p.seq_num(33);
	p.qos_control(2); // TID=2
	p.more_frag(1);

	const auto captured = inject_and_capture(sout, sin, p, channel, 1);
	if(captured.empty()) log(LogLevel::ERROR, "[-] Unable to inject frame with More Fragment flag using {}.", strtype);
	else log(LogLevel::INFO, "[+] Properly captured injected frame with More Fragment flag using {}.", strtype);
	return captured.empty() ? FLAG_FAIL : 0;
}

int hw_capabilities::test_injection_fields(MonitorSocket &sout, MonitorSocket &sin, const Dot11Ref &ref,
											const string &strtype, const int channel
){
	log(LogLevel::INFO, "--- Testing injection of fields using {}", strtype);
	int status = 0;

	// Apply ref addresses/flags to any frame type
	auto apply = [&](auto &frame){
		frame.addr1(ref.addr1);
		frame.addr2(ref.addr2);
		frame.addr3(ref.addr3);
		if(ref.from_ds) frame.from_ds(1);
		if(ref.to_ds) frame.to_ds(1);
	};

	// 1. Basic data frame delivery
	{
		Dot11Data p;
		apply(p);
		p.seq_num(30);
		status |= test_packet_injection(sout, sin, p, [](const vector<uint8_t> &){ return true; },
										"EAPOL frame with " + strtype, "Injected {} was not captured!", channel);
	}
	// 2. Sequence number preserved
	{
		Dot11Data p;
		apply(p);
		p.seq_num(31);
		status |= test_packet_injection(sout, sin, p, [](const vector<uint8_t> &raw){
			try{
				const RadioTap rt(raw.data(), raw.size());
				const auto *d = rt.find_pdu<Dot11Data>();
				return d && d->seq_num() == 31;
			} catch(...){ return false; }
		}, "empty data frame with " + strtype, "Sequence number of injected {} is being overwritten!", channel);
	}
	// 3. Fragment number preserved
	{
		Dot11Data p;
		apply(p);
		p.seq_num(32);
		p.frag_num(1);
		status |= test_packet_injection(sout, sin, p, [](const vector<uint8_t> &raw){
											try{
												const RadioTap rt(raw.data(), raw.size());
												const auto *d = rt.find_pdu<Dot11Data>();
												return d && d->frag_num() == 1;
											} catch(...){ return false; }
										}, "fragmented empty data frame with " + strtype,
										"Fragment number of injected {} is being overwritten!",
										channel);
	}
	// 4. QoS TID preserved
	{
		Dot11QoSData p;
		apply(p);
		p.seq_num(33);
		p.qos_control(2); // TID=2
		status |= test_packet_injection(sout, sin, p, [](const vector<uint8_t> &raw){
			try{
				const RadioTap rt(raw.data(), raw.size());
				const auto *q = rt.find_pdu<Dot11QoSData>();
				return q && (q->qos_control() & 0xF) == 2;
			} catch(...){ return false; }
		}, "empty QoS data frame with " + strtype, "QoS TID of injected {} is being overwritten!", channel);
	}
	// 5. A-MSDU bit + TID preserved
	{
		Dot11QoSData p;
		apply(p);
		p.seq_num(33);
		p.qos_control(2 | 0x80); // TID=2, A-MSDU present
		status |= test_packet_injection(sout, sin, p, [](const vector<uint8_t> &raw){
			try{
				const RadioTap rt(raw.data(), raw.size());
				const auto *q = rt.find_pdu<Dot11QoSData>();
				return q && (q->qos_control() & 0xF) == 2 && (q->qos_control() & 0x80);
			} catch(...){ return false; }
		}, "A-MSDU frame with " + strtype, "A-MSDU {} is not properly injected!", channel);
	}

	if(status == 0) log(LogLevel::INFO, "[+] All tested fields are properly injected when using {}.", strtype);
	return status;
}

int hw_capabilities::test_injection_order(MonitorSocket &sout, MonitorSocket &sin, const Dot11Ref &ref,
										const string &strtype, const int channel, const int retries
){
	log(LogLevel::INFO, "--- Testing order of injected QoS frames using {}", strtype);

	const auto label = make_label();

	auto make_qos = [&](const uint8_t tid) ->Dot11QoSData{
		Dot11QoSData p;
		p.addr1(ref.addr1);
		p.addr2(ref.addr2);
		if(ref.from_ds) p.from_ds(1);
		if(ref.to_ds) p.to_ds(1);
		p.seq_num(33);
		p.qos_control(tid);
		p.inner_pdu(new RawPDU(label.data(), label.size()));
		return p;
	};
	auto p2 = make_qos(2), p6 = make_qos(6);

	vector<int> tids;
	for(int i = 0; i <= retries; i++){
		// 4×TID2 to fill/busy the Tx queue, then TID6 to test ordering
		for(int j = 0; j < 4; j++) sout.send(p2, channel);
		sout.send(p6, channel);

		const auto deadline = steady_clock::now() + milliseconds(2500);
		tids.clear();
		while(steady_clock::now() < deadline){
			auto r = sin.recv();
			if(!r){
				this_thread::sleep_for(milliseconds(1));
				continue;
			}
			if(ranges::search(r.raw, label).empty()) continue;
			try{
				const RadioTap rt(r.raw.data(), r.raw.size());
				if(const auto *q = rt.find_pdu<Dot11QoSData>()) tids.push_back(q->qos_control() & 0xF);
			} catch(...){}
		}

		string tid_str = "[";
		for(size_t k = 0; k < tids.size(); k++){
			if(k) tid_str += ", ";
			tid_str += to_string(tids[k]);
		}
		log(LogLevel::INFO, "Captured TIDs: {}", tid_str + "]");

		if(ranges::contains(tids, 2) && ranges::contains(tids, 6)) break;
		log(LogLevel::INFO, "We didn't capture all injected QoS TID frames, retrying.");
	}

	if(!ranges::contains(tids, 2) || !ranges::contains(tids, 6)){
		log(LogLevel::ERROR, "[-] We didn't capture all injected QoS TID frames with {}. Test failed.", strtype);
		return FLAG_NOCAPTURE;
	}
	auto sorted = tids;
	ranges::sort(sorted);
	if(tids != sorted){
		log(LogLevel::ERROR, "[-] Frames with different QoS TIDs are reordered during injection with {}.", strtype);
		return FLAG_FAIL;
	}
	log(LogLevel::INFO, "[+] Frames with different QoS TIDs are not reordered during injection with {}.", strtype);
	return 0;
}

void hw_capabilities::test_injection_retrans(MonitorSocket &sout, MonitorSocket &sin, const HWAddress<6> &addr1,
											const HWAddress<6> &addr2, const int channel
){
	bool suspicious = false, test_fail = false;

	auto make_frame = [&](const HWAddress<6> &a1, const HWAddress<6> &a2) ->Dot11Data{
		Dot11Data p;
		p.to_ds(1);
		p.addr1(a1);
		p.addr2(a2);
		p.seq_num(33);
		return p;
	};

	// 1. Retransmission count (dummy MACs → no ACK expected → driver retransmits)
	{
		auto p = make_frame({"00:11:00:00:02:01"}, {"00:11:00:00:02:01"});
		const auto num = static_cast<int>(inject_and_capture(sout, sin, p, channel, 0, 1).size());
		log(LogLevel::INFO, "Injected frames seem to be (re)transmitted {} times", num);
		if(num == 0){
			log(LogLevel::ERROR, "Couldn't capture injected frame. Please restart the test.");
			test_fail = true;
		} else if(num == 1){
			log(LogLevel::WARNING, "Injected frames don't seem to be retransmitted!");
			suspicious = true;
		}
	}
	// 2. Spoofed sender → AP still retransmits?
	{
		auto p = make_frame(addr1, {"00:22:00:00:00:01"});
		const auto num = static_cast<int>(inject_and_capture(sout, sin, p, channel, 0, 1).size());
		log(LogLevel::INFO, "Captured {} (re)transmitted frames to the AP when using a spoofed sender address", num);
		if(num == 0){
			log(LogLevel::ERROR, "Couldn't capture injected frame. Please restart the test.");
			test_fail = true;
		}
		if(num > 2)
			log(LogLevel::INFO,
				"  => Acknowledged frames with a spoofed sender address are still retransmitted. This has low impact.");
	}
	// 3. Real sender → ACKed?
	{
		auto p = make_frame(addr1, addr2);
		const auto num = static_cast<int>(inject_and_capture(sout, sin, p, channel, 0, 1).size());
		log(LogLevel::INFO, "Captured {} (re)transmitted frames to the AP when using the real sender address", num);
		if(num == 0){
			log(LogLevel::ERROR, "Couldn't capture injected frame. Please restart the test.");
			test_fail = true;
		} else if(num > 2){
			log(LogLevel::INFO,
				"  => Acknowledged frames with real sender address are still retransmitted. This might impact time-sensitive tests.");
			suspicious = true;
		}
	}

	if(suspicious) log(LogLevel::WARNING,
						"[-] Retransmission behaviour isn't ideal. This test can be unreliable (e.g. due to background noise).");
	else if(!test_fail) log(LogLevel::INFO,
							"[+] Retransmission behaviour is good. This test can be unreliable (e.g. due to background noise).");
}

int hw_capabilities::test_injection_txack(MonitorSocket &sout, MonitorSocket &sin, const HWAddress<6> &dest_mac,
										const HWAddress<6> &own_mac, const int channel
){
	Dot11ProbeRequest probe;
	probe.addr1(dest_mac);
	probe.addr2(own_mac);
	probe.addr3(dest_mac);
	probe.seq_num(33);
	probe.ssid(""); // wildcard/broadcast probe

	const auto [rx_probes, tx_acks] = capture_probe_response_ack(sout, sin, probe, channel, 1);
	log(LogLevel::INFO, "Captured {} probe responses and {} ACKs in response.", rx_probes.size(), tx_acks.size());
	if(rx_probes.empty()){
		log(LogLevel::ERROR, "Didn't receive a probe response to test ack generation. Re-run the test.");
		return FLAG_NOCAPTURE;
	}
	if(tx_acks.empty()){
		log(LogLevel::WARNING, "[-] Acknowledgement frames aren't sent when receiving a frame.");
		return FLAG_FAIL;
	}
	log(LogLevel::INFO, "[+] Acknowledgement frames are sent when receiving a frame.");
	return 0;
}
}
