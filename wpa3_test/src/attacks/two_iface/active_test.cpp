#include "attacks/two_iface/active_test.h"
#include "config/RunStatus.h"
#include "config/actor_keys.h"
#include "system/hw_capabilities.h"
#include <fstream>
#include <nlohmann/json.hpp>

namespace wpa3_tester::active_test {
using namespace std;
using namespace filesystem;
using nlohmann::json;

void setup_attack(RunStatus &rs){}

void run_attack(RunStatus &rs) {
	auto &actor1 = rs.get_actor("transceiver");
	auto &actor2 = rs.get_actor("receiver");

	const json result = {
		{"acked", ok1},
		{"not_acked", ok2},
		{"success",  /* 95%+ acked-> true*/},
	};

	const path result_path = rs.run_folder() / "result.json";
	ofstream ofs(result_path);
	ofs << result.dump(2);
}

void stats_attack(const RunStatus &rs) {}

}
