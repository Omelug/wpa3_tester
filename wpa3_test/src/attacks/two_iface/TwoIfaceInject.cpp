#include "attacks/two_iface/TwoIfaceInject.h"

#include <filesystem>
#include <fstream>

#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "setup/config_parser.h"
#include "system/injection_result.h"

namespace wpa3_tester {
using namespace std;
using namespace filesystem;
using nlohmann::json;

TwoIfaceInject::TwoIfaceInject()
: TwoIface({{SK::driver_name, SK::driver_hash, SK::module_hash, SK::permanent_mac}, {BK::monitor}}, "two_iface_inject"){}

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
				{"netns", "tx"}
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

	RunStatus rs(config_path, "injection_test", "two_iface/injection_test");
	rs.run_folder(lr_dir);
	rs.execute();

	const path result_path = rs.run_folder() / "result.json";
	if(!exists(result_path))
		return json{{"err_msg", "result_path dont exists"}};

	ifstream ifs(result_path);
	const auto result = json::parse(ifs, nullptr, false);
	return result.is_discarded() ? json{{"err_msg", "result is discarded"}} : result;
}

bool TwoIfaceInject::run_check(const ActorPtr &a1, const ActorPtr &a2, const CacheBehave behave, const string &injection_key){
	TwoIfaceInject t;
	const auto [result, from_cache] = t.validate(a1, a2, behave);

	const auto fail = [&](const string &key){
		throw req_err(
			"inject_test " + key + ": "
			+ a1->get_or(SK::actor_name, "?")
			+ "/" + a2->get_or(SK::actor_name, "?")
			+ " failed injection check");
	};

	if(injection_key == "injection"){
		for(const auto &[key, val] : result.at("tests").items())
			if(it_test_result_from_string(val.at("result").get<std::string>()) != PASSED) fail(key);
	} else {
		if(it_test_result_from_string(result.at("tests").at(injection_key).at("result").get<std::string>()) != PASSED)
			fail(injection_key);
	}
	return !from_cache;
}
}
