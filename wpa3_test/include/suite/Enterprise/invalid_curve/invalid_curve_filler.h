#pragma once
#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite::invalid_curve_filler{

void setup_suite(const RunSuiteStatus &rss);
void generate_report(RunSuiteStatus &rss);

}