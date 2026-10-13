#pragma once
#include <string>
#include "config/RunStatus.h"

namespace wpa3_tester::observer::wpa_cli_poller {
inline const std::string SUFFIX_wpa = "_wpa_cli";

void start_wpa_cli_polling(RunStatus &rs, const std::string &actor_name, int interval_sec);
}
