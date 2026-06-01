#pragma once
#include <filesystem>
#include <string>

#include "config/RunSuiteStatus.h"

namespace wpa3_tester::suite{

std::string section_title(const std::filesystem::path &rel);
void generate_suite_report(RunSuiteStatus &rss);

}
