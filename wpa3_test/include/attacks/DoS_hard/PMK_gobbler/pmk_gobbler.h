#pragma once
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <tins/hw_address.h>
#include "config/RunStatus.h"

namespace wpa3_tester::pmk_gobbler{
    struct ACMCookie {
        Tins::HWAddress<6> sta_mac;
        std::vector<uint8_t> token;
    };

    struct CookieStore {
        std::deque<ACMCookie> queue;
        std::mutex mtx;
        std::atomic<bool> stop{false};
    };

    std::optional<ACMCookie> parse_acm_response(const uint8_t *packet, const uint32_t len) ;

    void capture_cookies(const std::string &sniff_iface,
                         const Tins::HWAddress<6> &ap_mac,
                         CookieStore &store);

    ACMCookie trigger_acm(const std::string &iface, const std::string &sniff_iface,
                          const Tins::HWAddress<6> &ap_mac,
                          int trigger_count);

    void burst_with_cookies(const std::string &iface,
                            const Tins::HWAddress<6> &ap_mac,
                            CookieStore &store,
                            int attack_time_sec);

    void run_attack(RunStatus &rs);
    void stats_attack(const RunStatus &rs);
}