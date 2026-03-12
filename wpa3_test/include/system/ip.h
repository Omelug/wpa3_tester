#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester::ip{
    void set_ip(RunStatus& run_status, const std::string &actor_name);
    std::string resolve_host(const std::string& hostname);
    std::string get_ip(const std::string& iface);
    static bool ping(const std::string& ip, const int timeout_sec = 2);
    static string get_mac_by_ip(const std::string& ip);
}
