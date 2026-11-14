#include "attacks/two_iface/TwoIfaceActive.h"
#include <filesystem>
#include <fstream>

#include "config/RunStatus.h"
#include "default.h"
#include "logger/error_log.h"
#include "setup/config_parser.h"

namespace wpa3_tester {
using namespace std;
using namespace filesystem;
using nlohmann::json;

TwoIfaceActive::TwoIfaceActive():
	TwoIface({ { SK::driver_name, SK::driver_hash, SK::module_hash, SK::permanent_mac },
				 { BK::monitor, BK::active_monitor } },
		"active_test") {}

json TwoIfaceActive::run(const ActorPtr &a1, const ActorPtr &a2) {
	// Generate config to data/two_iface/active_test/config/<file>
	const json config = {
		{ "name", "active_test" },
		{ "attacker_module", "active_test" },
		{ "delete_old", true },
		{ "rewrite", "all" },
		{ "actors",
			{
				{ "transceiver", { { "source", "internal" }, { "selection", make_selection(a1) }, { "netns", "tx" } } },
				{ "receiver",
					{
						{ "source", "internal" },
						{ "selection", make_selection(a2) },
					} },
			} },
	};

	const path config_dir = cache_folder() / "config";
	create_directories(config_dir);
	const path config_path = config_dir / "last_run_config.yaml";
	save_yaml(config, config_path);

	RunStatus rs(config_path.string(), "active_test", "two_iface/active_test");
	rs.run_folder(cache_folder() / "run");
	rs.execute();

	// Read back result.json written by run_attack
	const path result_path = rs.run_folder() / RESULT_NAME;
	if(!exists(result_path)) return json{ { "err_msg", "result_path dont exists" }, { "success", false } };

	ifstream ifs(result_path);
	const auto result = json::parse(ifs, nullptr, false);
	return result.is_discarded() ? json{ { "err_msg", "result is discarded" }, { "success", false } } : result;
}

void TwoIfaceActive::backfill_cache(const ActorPtr &a1, const ActorPtr &a2, const json &result) {
	const TwoIfaceActive t;
	t.write_cache(t.make_cache_key(a1, a2), result);
}

optional<bool> TwoIfaceActive::find_cache_needs_active(const ActorPtr &acker) {
	TwoIfaceActive t;
	const ParamFilter sk_only{t.cache_id.first, {}};
	const string a1_prefix = acker->to_str(&sk_only);

	const path cp = t.cache_path();
	if(!exists(cp)) return nullopt;

	ifstream ifs(cp);
	string line;
	while(getline(ifs, line)) {
		if(line.empty()) continue;
		const auto tab = line.find('\t');
		if(tab == string::npos) continue;
		const string key = line.substr(0, tab);
		const auto sep = key.find('|');
		if(sep == string::npos) continue;
		// rogue_sta is the ACKer (receiver/a2) in the active_test
		const string a2_part = key.substr(sep + 1);
		if(a2_part.rfind(a1_prefix, 0) != 0) continue;

		const auto j = json::parse(line.substr(tab + 1), nullptr, false);
		if(j.is_discarded() || !j.value("success", false)) continue;

		log(LogLevel::INFO, "prefer_active: found first successful cache entry: {}", key);
		const auto pos = a2_part.find("active_monitor");
		return pos != string::npos && (pos == 0 || a2_part[pos - 1] != '!');
	}
	return nullopt;
}

bool TwoIfaceActive::run_check(const ActorPtr &a1, const ActorPtr &a2, const CacheBehave behave) {
	TwoIfaceActive t;
	const auto [result, from_cache] = t.validate(a1, a2, behave);
	if(!result.value("success", false)) {
		throw req_err("active_test: actors " + a1.get(SK::actor_name) + "/" + a2.get(SK::actor_name) +
			" failed active monitor check");
	}
	return !from_cache;
}
}
