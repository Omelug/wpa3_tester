#pragma once
#include <filesystem>

namespace wpa3_tester::test_helpers{
// Redirects wpa3_tester::root_dir() to a fresh temp fixture directory with a minimal
// attack_config/global_config.yaml, and force-reloads the process-wide global_config
// cache to match, so code paths that touch data/cache, attack_config/, etc. don't read
// or write real project files during a test. Restores both on destruction.
struct IsolatedRootDir{
	std::filesystem::path dir;
	std::filesystem::path real_root;

	explicit IsolatedRootDir(const std::string &name);
	~IsolatedRootDir();
};
}
