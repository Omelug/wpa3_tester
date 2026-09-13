#pragma once
#include <filesystem>
#include <string>

namespace wpa3_tester::overview {
std::string lookup_vendor(const std::filesystem::path &manuf_file, const std::string &mac);
}
