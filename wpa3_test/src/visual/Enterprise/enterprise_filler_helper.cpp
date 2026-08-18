#include "default.h"
#include "config/RunSuiteStatus.h"
#include "system/utils.h"

namespace wpa3_tester::suite::enterprise_filler_helper{
void setup_suite(const RunSuiteStatus &rss){

	const auto base_dir = rss.run_folder() / TEST_SUITE_CONFIG_DIR;

	for (const auto& entry : std::filesystem::directory_iterator(base_dir)) {
		if (is_directory(entry.path())) {
			const auto config_dir = entry.path() / "config";
			create_public_dirs(config_dir);

			copy_f(rss.config_path().parent_path() / "config/hostapd.eap_user", config_dir / "hostapd.eap_user");
			copy_f(rss.config_path().parent_path() / "config/hostapd.conf", config_dir / "hostapd.conf");
		}
	}
}
}
