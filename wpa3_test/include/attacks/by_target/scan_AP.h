#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::attack_scan{
    class Scan_STA{
    public:
        std::string mac;
        explicit Scan_STA(std::string m) : mac(std::move(m)) {}

        bool operator<(const Scan_STA& other) const {
            return this->mac < other.mac;
        }

        bool operator==(const Scan_STA& other) const {
            return this->mac == other.mac;
        }
    };

    class ScanAP{
    public:
        std::string ssid;
        Tins::Dot11Beacon beacon;
        std::optional<Tins::RSNInformation> rsn;
        std::set<Scan_STA> stations;
        std::string bssid;

        static std::string to_tshark_str(const std::filesystem::path &beacon_path);
        static void print_AKMs(std::stringstream &ss, const Tins::RSNInformation::akm_type &akms);
        std::string to_str() const;
    };

    void run_attack(RunStatus& rs);
}
