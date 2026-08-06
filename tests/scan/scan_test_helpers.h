#pragma once
#include "config/RunStatus.h"

namespace wpa3_tester {
// Exposes protected scanning methods so they can be exercised in unit tests
// without modifying production logic.
class TestableRunStatus : public RunStatus {
public:
	void set_config(const nlohmann::json &j){ _config = j; }
	using RunStatus::get_external_BB_channels;
	using RunStatus::external_bb_options;
	using RunStatus::process_single_packet;
	using RunStatus::scan_until_match;
};
}
