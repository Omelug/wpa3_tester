#pragma once
#include <libtins-src/include/tins/rsn_information.h>
#include "config/RunStatus.h"

namespace wpa3_tester::attack_scan{
    class Station_info{
        std::string mac;
    };
    class Scan_AP{
    public:
        std::string ssid;
        Tins::RSNInformation rsn;
        std::map<std::string, Station_info> stations;

        std::string to_str() const{
           return "SSID: "+ssid;
        };
    };
    void run_attack(RunStatus& rs);
}
