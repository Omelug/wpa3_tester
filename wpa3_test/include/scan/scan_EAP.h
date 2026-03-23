#pragma once
#include <filesystem>
#include <vector>

#include "config/Actor_config.h"

namespace wpa3_tester::scan{
    void active_eap_identity_scan(const std::string& iface, const std::string& target_ap_mac, int timeout_sec);
}