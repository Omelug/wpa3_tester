#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::attack_scan{
    class Scan_STA{
        std::string mac;
    };

    class ScanAP{
    public:
        std::string ssid;
        Tins::Dot11Beacon beacon;
        std::optional<Tins::RSNInformation> rsn;
        std::map<std::string, Scan_STA> stations;

        static std::string to_tshark_str(const std::filesystem::path &beacon_path);
        static void print_AKMs(std::stringstream &ss, const Tins::RSNInformation::akm_type &akms);
        std::string to_str() const;
    };
    void run_attack(RunStatus& rs);
}
