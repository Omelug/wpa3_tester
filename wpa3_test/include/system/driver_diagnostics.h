#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace wpa3_tester::driver_diag{

// collects best-effort driver-specific diagnostics from debugfs for
// drivers groups: (mt76, rtw88, rtw89, ath9k_htc, rtl8xxxu)

// ABI stability NOT guarantee
// there are no stability constraints placed on files exported there
// https://docs.kernel.org/filesystems/debugfs.html
nlohmann::json collect_driver_specific(const std::string &driver_name, const std::string &phy);
std::string summarize_driver_specific(const nlohmann::json &driver_specific);

}