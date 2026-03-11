#pragma once
#include <filesystem>
#include <vector>

#include "config/Actor_config.h"

namespace wpa3_tester::scan{
    static std::vector<std::string> parse_csv_line(const std::string& line);
    std::vector<std::unique_ptr<Actor_config>> get_actors_conn_table(const std::filesystem::path& conn_table);
}
