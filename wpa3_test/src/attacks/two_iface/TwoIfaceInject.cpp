#include "attacks/two_iface/TwoIfaceInject.h"
#include <filesystem>
#include <fstream>
#include "config/RunStatus.h"
#include "logger/log.h"
#include "setup/config_parser.h"

namespace wpa3_tester {
using namespace std;
using namespace filesystem;
using nlohmann::json;

TwoIfaceInject::TwoIfaceInject()
: TwoIface({{SK::driver_name, SK::driver_hash, SK::permanent_mac}, {BK::injection, BK::monitor}}, "two_iface_inject"){}

json TwoIfaceInject::run(const ActorPtr &t, const ActorPtr &r){
	const json config = {
		{"name",            "injection_test"},
		{"attacker_module", "injection_test"},
		{"delete_old",      true},
		{"rewrite",         "all"},
		{"actors", {
			{"transceiver", {
				{"source",    "internal"},
				{"selection", make_selection(t)},
			}},
			{"receiver", {
				{"source",    "internal"},
				{"selection", make_selection(r)},
			}},
		}},
	};

	const path config_dir = cache_folder() / "config";
	const path lr_dir     = cache_folder() / "last_run";
	create_directories(config_dir);
	const path config_path = config_dir / "last_run_config.yaml";
	save_yaml(config, config_path);

	RunStatus rs(config_path.string(), "injection_test", "two_iface/injection_test");
	rs.run_folder(lr_dir);
	rs.execute();

	const path result_path = rs.run_folder() / "result.json";
	if(!exists(result_path))
		return json{{"err_msg", "result_path dont exists"}, {"overall_flags", 1}};

	ifstream ifs(result_path);
	const auto result = json::parse(ifs, nullptr, false);
	return result.is_discarded() ? json{{"err_msg", "result is discarded"}, {"overall_flags", 1}} : result;
}

bool TwoIfaceInject::run_check(const ActorPtr &a1, const ActorPtr &a2){
	TwoIfaceInject t;
	const auto [result, from_cache] = t.validate(a1, a2);
	if(result.value("overall_flags", 1) != 0)
		log(LogLevel::WARNING, "inject_test: actors {}/{} failed injection check",
			a1[SK::actor_name].value_or("?"), a2[SK::actor_name].value_or("?"));
	return from_cache;
}

}
