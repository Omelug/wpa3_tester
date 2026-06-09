#pragma once
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite::wpa3_trans_downgrade_filler{

void setup_suite(const RunSuiteStatus &rss);
void generate_report(RunSuiteStatus &rss);

}