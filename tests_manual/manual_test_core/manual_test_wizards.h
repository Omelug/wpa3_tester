#pragma once
#include <string>
#include <vector>
#include "config/RunStatus.h"

namespace wpa3_tester::manual_tests {
    void cli_section(const std::string& section_title);
    std::string get_iface_wizard();
    void print_external_entities(const std::vector<ExternalEntity>& entities);
}

