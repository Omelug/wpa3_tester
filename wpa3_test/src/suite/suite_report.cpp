#include <functional>
#include <map>
#include <string>

#include "config/RunStatus.h"

std::map<std::pmr::string,std::function<void(wpa3_tester::RunStatus&)>> suite_report_map = {
    //{"hostapd_versions", generate_report}
};