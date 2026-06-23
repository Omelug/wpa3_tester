#pragma once
#include <filesystem>

namespace wpa3_tester::overview {
void generate_malformed_eapol1(const std::filesystem::path &output_dir, const std::filesystem::path &data_dir);
}
