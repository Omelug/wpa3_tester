#include "system/hw_capabilities.h"
#include <algorithm>
#include <chrono>
#include <random>
#include <thread>
#include <vector>
#include <tins/tins.h>
#include "attacks/mc_mitm/MonitorSocket.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "system/injection_result.h"

namespace wpa3_tester{
using namespace std;
using namespace Tins;
using namespace chrono;

//TODO simplifi test
static vector<uint8_t> make_label(){
	static mt19937 rng{random_device{}()};
	uniform_int_distribution<uint32_t> dist;
	vector<uint8_t> label = {'A', 'A', 'A', 'A'};
	// two random uint32 big-endian (matches Python struct.pack(">II", ...))
	for(const uint32_t v: {dist(rng), dist(rng)})
		for(int i = 3; i >= 0; i--) label.push_back((v >> (i * 8)) & 0xFF);
	return label;
}


vector<vector<uint8_t>> hw_capabilities::inject_and_capture(
	MonitorSocket &sout, MonitorSocket &sin, PDU &pdu,
	const Channel ch, const int count, const int retries
){
	const auto label = make_label();

	auto frame = unique_ptr<PDU>(pdu.clone());
	frame->inner_pdu(new RawPDU(label.data(), label.size()));

	const auto *d11 = pdu.find_pdu<Dot11>();
	const bool has_mf = d11 && d11->more_frag();

	vector<vector<uint8_t>> captured;
	int attempt = 0;
	while(true){
		sout.send(*frame, ch);

		if(sout.mf_workaround && has_mf){
			if(const auto *qos = pdu.find_pdu<Dot11QoSData>()){
				Dot11QoSData fix;
				fix.qos_control(qos->qos_control() & 0x000F);
				sout.send(fix, ch);
			} else{
				Dot11Data fix;
				sout.send(fix, ch);
			}
		}

		const auto deadline = steady_clock::now() + seconds(1);
		while(steady_clock::now() < deadline){
			auto r = sin.recv();
			if(!r){ this_thread::sleep_for(milliseconds(1)); continue; }
			if(!ranges::search(r.raw, label).empty()){
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
	for(int i = 0; i < 10000 && s.recv(); i++); //FIXME 10000 hardcoded
}

optional<pair<HWAddress<6>, string>> hw_capabilities::get_nearby_ap_addr(MonitorSocket &sin){
	struct Entry{ int8_t rssi; HWAddress<6> mac; string ssid; };
	vector<Entry> beacons;
	const auto deadline = steady_clock::now() + milliseconds(500);
	while(steady_clock::now() < deadline){
		auto r = sin.recv();
		if(!r){ this_thread::sleep_for(milliseconds(1)); continue; }
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

ProbeCapture hw_capabilities::capture_probe_response_ack(
	MonitorSocket &sout, MonitorSocket &sin, PDU &probe_req,
	const Channel ch, const int retries
){
	const auto [addr1, addr2] = get_addrs(probe_req, {});
	if(addr2 == HWAddress<6>()) return {};
	const auto src = addr2;
	const auto dst = addr1;

	ProbeCapture result;
	int attempt = 0;
	while(true){
		flush_socket(sin);
		sout.send(probe_req, ch);
		const auto deadline = steady_clock::now() + seconds(1);
		while(steady_clock::now() < deadline){
			auto r = sin.recv();
			if(!r){ this_thread::sleep_for(milliseconds(1)); continue; }
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
		attempt++;
	}
	return result;
}

InjectionTestResult hw_capabilities::test_packet_injection(
	MonitorSocket &sout, MonitorSocket &sin, PDU &pdu,
	const function<bool(const vector<uint8_t> &)> &test_func,
	const string &name, const string &msgfail, const Channel ch
){
	const auto packets = inject_and_capture(sout, sin, pdu, ch, 1);
	if(packets.empty()) return {name, NOCAPTURE, "no capture"};
	if(!ranges::all_of(packets, test_func)) return {name, FAIL, msgfail};
	return {name, PASSED};
}

InjectionTestResult hw_capabilities::test_injection_more_fragments(
	MonitorSocket &sout, MonitorSocket &sin,
	const Dot11Ref &ref, const string &strtype, const Channel ch
){
	Dot11QoSData p;
	p.addr1(ref.addr1); p.addr2(ref.addr2);
	if(ref.from_ds) p.from_ds(1);
	if(ref.to_ds)   p.to_ds(1);
	p.seq_num(33); p.qos_control(2); p.more_frag(1);

	const auto captured = inject_and_capture(sout, sin, p, ch, 1);
	return {"injection_more_fragments_" + strtype, captured.empty() ? FAIL : PASSED};
}

InjectionTestResult hw_capabilities::test_injection_fields(
	MonitorSocket &sout, MonitorSocket &sin,
	const Dot11Ref &ref, const string &strtype, const Channel ch
){
	auto apply = [&](auto &frame){
		frame.addr1(ref.addr1); frame.addr2(ref.addr2); frame.addr3(ref.addr3);
		if(ref.from_ds) frame.from_ds(1);
		if(ref.to_ds)   frame.to_ds(1);
	};

	it_test_result result = PASSED;
	string failed;

	auto run = [&](auto &pdu,
	               const function<bool(const vector<uint8_t> &)> &fn,
	               const string &name, const string &msg){
		const auto r = test_packet_injection(sout, sin, pdu, fn, name, msg, ch);
		if(r.result() != PASSED){
			if(result == PASSED) result = r.result();
			failed += name + " ";
		}
	};

	// 1. Delivery
	Dot11Data p1; apply(p1); p1.seq_num(30);
	run(p1, [](const vector<uint8_t> &){ return true; }, "eapol", "not captured");

	// 2. Seq num preserved
	Dot11Data p2; apply(p2); p2.seq_num(31);
	run(p2, [](const vector<uint8_t> &raw){
		try{ const RadioTap rt(raw.data(), raw.size());
		     const auto *d = rt.find_pdu<Dot11Data>();
		     return d && d->seq_num() == 31; } catch(...){ return false; }
	}, "seq_num", "sequence number overwritten");

	// 3. Frag num preserved
	Dot11Data p3; apply(p3); p3.seq_num(32); p3.frag_num(1);
	run(p3, [](const vector<uint8_t> &raw){
		try{ const RadioTap rt(raw.data(), raw.size());
		     const auto *d = rt.find_pdu<Dot11Data>();
		     return d && d->frag_num() == 1; } catch(...){ return false; }
	}, "frag_num", "fragment number overwritten");

	// 4. QoS TID preserved
	Dot11QoSData p4; apply(p4); p4.seq_num(33); p4.qos_control(2);
	run(p4, [](const vector<uint8_t> &raw){
		try{ const RadioTap rt(raw.data(), raw.size());
		     const auto *q = rt.find_pdu<Dot11QoSData>();
		     return q && (q->qos_control() & 0xF) == 2; } catch(...){ return false; }
	}, "qos_tid", "QoS TID overwritten");

	// 5. A-MSDU bit + TID preserved
	Dot11QoSData p5; apply(p5); p5.seq_num(33); p5.qos_control(2 | 0x80);
	run(p5, [](const vector<uint8_t> &raw){
		try{ const RadioTap rt(raw.data(), raw.size());
		     const auto *q = rt.find_pdu<Dot11QoSData>();
		     return q && (q->qos_control() & 0xF) == 2 && (q->qos_control() & 0x80); }
		catch(...){ return false; }
	}, "a-msdu", "A-MSDU not properly injected");

	return {"injection_fields_order_" + strtype, result, failed};
}

InjectionTestResult hw_capabilities::test_injection_order(
	MonitorSocket &sout, MonitorSocket &sin,
	const Dot11Ref &ref, const string &strtype, const Channel ch, const int retries
){
	// New label per retry round — frames from a previous round that arrive late
	// (ath9k_htc retransmits until ACK, can take >2.5 s) won't match the new label
	// and won't pollute the ordering check.
	auto make_qos = [&](const uint8_t tid, const vector<uint8_t> &lbl) -> Dot11QoSData{
		Dot11QoSData p;
		p.addr1(ref.addr1); p.addr2(ref.addr2);
		if(ref.from_ds) p.from_ds(1);
		if(ref.to_ds)   p.to_ds(1);
		p.seq_num(33); p.qos_control(tid);
		p.inner_pdu(new RawPDU(lbl.data(), lbl.size()));
		return p;
	};

	vector<int> tids;
	this_thread::sleep_for(milliseconds(4000)); //FIXME dont pass without this, bas setup ?, driver issues?
	for(int i = 0; i <= retries; i++){
		const auto label = make_label(); // fresh label isolates this round
		auto p2 = make_qos(2, label), p6 = make_qos(6, label);

		for(int j = 0; j < 4; j++) sout.send(p2, ch);
		sout.send(p6, ch);
		tids.clear();

		const auto deadline = steady_clock::now() + milliseconds(2500);
		while(steady_clock::now() < deadline){
			auto r = sin.recv();
			if(!r){ this_thread::sleep_for(milliseconds(10)); continue; }
			if(ranges::search(r.raw, label).empty()) continue;
			try{
				const RadioTap rt(r.raw.data(), r.raw.size());
				const auto *q = rt.find_pdu<Dot11QoSData>();
				// Skip retransmissions (RETRY bit set); we only care about original TX order.
				if(q && !q->retry())
					tids.push_back(q->qos_control() & 0xF);
			} catch(...){}
		}
		if(ranges::contains(tids, 2) && ranges::contains(tids, 6)) break;
	}

	string tid_str;
	for(size_t k = 0; k < tids.size(); k++){ if(k) tid_str += ','; tid_str += to_string(tids[k]); }
	auto test_name = "injection_fields_order_"+strtype;
	if(!ranges::contains(tids, 2) || !ranges::contains(tids, 6))
		return {test_name, NOCAPTURE, "tids=[" + tid_str + "]"};

	auto sorted_tids = tids; ranges::sort(sorted_tids);
	if(tids != sorted_tids)
		return {test_name, FAIL, "reordered tids=[" + tid_str + "]"};

	return {test_name, PASSED, "tids=[" + tid_str + "]"};
}

InjectionTestResult hw_capabilities::test_injection_retrans(
	MonitorSocket &sout, MonitorSocket &sin,
	const HWAddress<6> &addr1, const HWAddress<6> &addr2, const Channel ch
){
	it_test_result result = PASSED;
	string detail;

	auto make_frame = [&](const HWAddress<6> &a1, const HWAddress<6> &a2) -> Dot11Data{
		Dot11Data p; p.to_ds(1); p.addr1(a1); p.addr2(a2); p.seq_num(33); return p;
	};

	auto count = [&](const HWAddress<6> &a1, const HWAddress<6> &a2) -> int{
		auto p = make_frame(a1, a2);
		return static_cast<int>(inject_and_capture(sout, sin, p, ch, 0, 1).size());
	};

	const int n_dummy   = count({"00:11:00:00:02:01"}, {"00:11:00:00:02:01"});
	const int n_spoofed = count(addr1, {"00:22:00:00:00:01"});
	const int n_real    = count(addr1, addr2);

	if(n_dummy == 0 || n_spoofed == 0 || n_real == 0){
		result = NOCAPTURE;
		detail += "no_capture ";
	}
	if(n_dummy == 1){
		result = FAIL;
		detail += "no_retrans ";
	}
	if(n_real > 2){
		result = FAIL;
		detail += "real_retrans_high ";
	}

	detail += "dummy=" + to_string(n_dummy)
	        + " spoofed=" + to_string(n_spoofed)
	        + " real=" + to_string(n_real);
	return {"injection_fields_retrans", result, detail};
}

InjectionTestResult hw_capabilities::test_injection_txack(
	MonitorSocket &sout, MonitorSocket &sin,
	const HWAddress<6> &dest_mac, const HWAddress<6> &own_mac, const Channel ch
){
	Dot11ProbeRequest probe;
	probe.addr1(dest_mac); probe.addr2(own_mac); probe.addr3(dest_mac);
	probe.seq_num(33);

	const auto [rx_probes, tx_acks] = capture_probe_response_ack(sout, sin, probe, ch, 1);

	if(rx_probes.empty())
		return {"test_injection_txack", NOCAPTURE, "no probe response"};
	if(tx_acks.empty())
		return {"test_injection_txack", FAIL, "no ACK generated"};
	return {"test_injection_txack", PASSED};
}

}
