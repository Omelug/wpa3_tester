#pragma once
#include <filesystem>

namespace wpa3_tester::overview {

void generate_wpa3_trans_downgrade(const std::filesystem::path &output_dir,
								   const std::filesystem::path &data_dir);

}
