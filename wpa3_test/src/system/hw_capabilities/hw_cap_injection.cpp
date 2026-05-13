#include "system/hw_capabilities.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <random>
#include <thread>
#include <vector>
#include <reproc++/drain.hpp>
#include <sys/wait.h>
#include <tins/tins.h>
#include "attacks/mc_mitm/MonitorSocket.h"
#include "config/global_config.h"
#include "config/RunStatus.h"
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
	vector<uint8_t> label = {'A','A','A','A'};
	// two random uint32 big-endian (matches Python struct.pack(">II", ...))
	for(const uint32_t v : {dist(rng), dist(rng)})
		for(int i = 3; i >= 0; i--) label.push_back((v >> (i * 8)) & 0xFF);
	return label;
}

vector<vector<uint8_t>> hw_capabilities::inject_and_capture(
	MonitorSocket &sout, MonitorSocket &sin,
	PDU &pdu, const int channel,
	const int count, const int retries
){
	const auto label = make_label();

	// Clone pdu and append label as Raw payload
	auto frame = unique_ptr<PDU>(pdu.clone());
	frame->innermost_pdu()->inner_pdu(new RawPDU(label.data(), label.size()));

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

}