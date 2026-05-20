#include "attacks/two_iface/TwoIfaceActive.h"
#include <filesystem>
#include <fstream>
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "setup/config_parser.h"

namespace wpa3_tester {
using namespace std;
using namespace filesystem;
using nlohmann::json;

TwoIfaceActive::TwoIfaceActive()
: TwoIface({
	{SK::driver_name, SK::driver_hash, SK::module_hash, SK::permanent_mac},
	{BK::monitor, BK::active_monitor}}, "active_test"){}

json TwoIfaceActive::run(const ActorPtr &a1, const ActorPtr &a2) {

	// Generate config to data/two_iface/active_test/config/<file>
	const json config = {
		{"name",            "active_test"},
		{"attacker_module", "active_test"},
		{"delete_old",      true},
		{"rewrite",         "all"},
		{"actors", {
			{"transceiver", {
				{"source",    "internal"},
				{"selection", make_selection(a1)},
			}},
			{"receiver", {
				{"source",    "internal"},
				{"selection", make_selection(a2)},
			}},
		}},
	};


	const path config_dir = cache_folder() / "config";
	const path lr_dir = cache_folder() / "last_run";
	create_directories(config_dir);
	const path config_path = config_dir / "last_run_config.yaml";
	save_yaml(config, config_path);

	RunStatus rs(config_path.string(), "active_test", "two_iface/active_test");
	rs.run_folder(lr_dir);
	rs.execute();

	// Read back result.json written by run_attack
	const path result_path = rs.run_folder() / "result.json";
	if(!exists(result_path))
		return json{{"err_msg", "result_path dont exists"}, {"success", false}};

	ifstream ifs(result_path);
	const auto result = json::parse(ifs, nullptr, false);
	return result.is_discarded() ? json{{"err_msg", "result is discarded"}, {"success", false}} : result;
}

bool TwoIfaceActive::run_check(const ActorPtr &a1, const ActorPtr &a2, const CacheBehave behave) {
	TwoIfaceActive t;
	const auto [result, from_cache] = t.validate(a1, a2, behave);
	if(!result.value("success", false)){
		throw req_err("active_test: actors "+a1.get(SK::actor_name)+"/"+a2.get(SK::actor_name)+" failed active monitor check");
	}
	return !from_cache;
}

}
