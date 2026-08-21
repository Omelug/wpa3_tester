#pragma once
#include <filesystem>

namespace wpa3_tester::overview {
void generate_mc_mitm(const std::filesystem::path &output_dir,
                      const std::filesystem::path &data_dir);
}
