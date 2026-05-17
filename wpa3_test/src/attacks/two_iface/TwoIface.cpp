#include "attacks/two_iface/TwoIface.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "attacks/mc_mitm/MonitorSocket.h"
#include <fstream>
#include <sstream>

namespace wpa3_tester{
using namespace std;
using namespace filesystem;
using nlohmann::json;

// ----- TwoIface base

TwoIface::TwoIface(CacheId id, string name)
: cache_id(std::move(id)), cache_name(std::move(name)){}

json TwoIface::validate(const ActorPtr &a1, const ActorPtr &a2, const CacheBehave behave){
	const string key = make_cache_key(a1, a2);

	if(!behave.force_run){
		const auto cached = lookup_cache(key);
		if(cached.has_value()) return *cached;

		if(behave.throw_on_miss) throw req_err("ERROR not found in cache " + cache_name);
		if(!behave.run_on_miss) return {};
	}

	const json result = run(a1, a2);

	const auto existing = lookup_cache(key);
	if(existing.has_value() && *existing != result){
		log(LogLevel::WARNING, "TwoIface cache '{}': result changed for key '{}'", cache_name, key);
	}

	write_cache(key, result);
	return result;
}

string TwoIface::make_cache_key(const ActorPtr &a1, const ActorPtr &a2) const{
	ostringstream oss;
	for(const SK sk: cache_id.first){
		oss << a1[sk].value_or("") << "|" << a2[sk].value_or("") << "|";
	}
	for(const BK bk: cache_id.second){
		oss << (a1[bk].value_or(false) ? "1" : "0") << (a2[bk].value_or(false) ? "1" : "0") << "|";
	}
	return oss.str();
}

optional<json> TwoIface::lookup_cache(const string &key) const{
	const path cp = cache_path();
	if(!exists(cp)) return nullopt;

	ifstream ifs(cp);
	string line;
	while(getline(ifs, line)){
		if(line.empty()) continue;
		const auto sep = line.find(',');
		if(sep == string::npos) continue;
		if(line.substr(0, sep) != key) continue;
		const auto j = json::parse(line.substr(sep + 1), nullptr, false);
		if(!j.is_discarded()) return j;
	}
	return nullopt;
}

void TwoIface::write_cache(const string &key, const json &result) const{
	const path cp = cache_path();
	create_directories(cp.parent_path());

	vector<string> lines;
	bool found = false;
	if(exists(cp)){
		ifstream ifs(cp);
		string line;
		while(getline(ifs, line)){
			if(line.empty()) continue;
			const auto sep = line.find(',');
			if(sep != string::npos && line.substr(0, sep) == key){
				lines.push_back(key + "," + result.dump());
				found = true;
			} else{
				lines.push_back(line);
			}
		}
	}
	if(!found) lines.push_back(key + "," + result.dump());

	ofstream ofs(cp, ios::out | ios::trunc);
	for(const auto &l: lines) ofs << l << "\n";
}

path TwoIface::cache_path() const{
	return path("data") / (cache_name + ".csv");
}

// TwoIfaceActive (active_test)

TwoIfaceActive::TwoIfaceActive()
: TwoIface({{SK::driver_name, SK::driver_hash}, {/*BK::monitor, BK::active_monitor*/}}, "two_iface_active"){}

json TwoIfaceActive::run(const ActorPtr &a1, const ActorPtr &a2){
	constexpr Channel ch = {};
	bool ok1 = false, ok2 = false;

	if(const auto &iface1 = a1[SK::iface]; iface1.has_value()){
		ok1 = hw_capabilities::set_monitor_active(*iface1, a1[SK::netns], ch);
		log(LogLevel::DEBUG, "active_test: {} -> {}", *iface1, ok1 ? "ok" : "fail");
	}
	if(const auto &iface2 = a2[SK::iface]; iface2.has_value()){
		ok2 = hw_capabilities::set_monitor_active(*iface2, a2[SK::netns], ch);
		log(LogLevel::DEBUG, "active_test: {} -> {}", *iface2, ok2 ? "ok" : "fail");
	}

	return json{{"actor1_ok", ok1}, {"actor2_ok", ok2}, {"both_ok", ok1 && ok2}};
}

bool TwoIfaceActive::run_check(const ActorPtr &a1, const ActorPtr &a2){
	TwoIfaceActive t;
	const bool both_ok = t.validate(a1, a2).value("both_ok", false);
	if(!both_ok)
		log(LogLevel::WARNING, "active_test: actors {}/{} failed active monitor check",
			a1[SK::actor_name].value_or("?"), a2[SK::actor_name].value_or("?"));
	return !both_ok; // true = need re-assignment
}

//------- TwoIfaceInject (inject_test)
TwoIfaceInject::TwoIfaceInject()
: TwoIface({{SK::driver_name, SK::driver_hash}, {/*BK::injection, BK::monitor*/}}, "two_iface_inject"){}

json TwoIfaceInject::run(const ActorPtr &a1, const ActorPtr &a2){
	const auto &iface1 = a1[SK::iface];
	const auto &iface2 = a2[SK::iface];

	if(!iface1.has_value() || !iface2.has_value()) throw setup_err(
		"inject_test: both actors must have an interface assigned");

	const Channel ch = a1->get_channel();
	hw_capabilities::setup_injection_iface(*iface1, ch, a1[SK::netns]);
	hw_capabilities::setup_injection_iface(*iface2, ch, a2[SK::netns]);

	MonitorSocket s_out(*iface1, a1[SK::netns]);
	MonitorSocket s_in(*iface2, a2[SK::netns]);

	const InjectionSuiteResult suite = hw_capabilities::run_injection_tests(s_out, *iface1, s_in, ch);

	const bool passed = (suite.overall_flags() == 0);
	log(passed ? LogLevel::INFO : LogLevel::WARNING, "inject_test: {}/{} -> {}", *iface1, *iface2,
		passed ? "passed" : "failed");

	return suite.to_json();
}

bool TwoIfaceInject::run_check(const ActorPtr &a1, const ActorPtr &a2){
	TwoIfaceInject t;
	const bool passed = (t.validate(a1, a2).value("overall_flags", 1) == 0);
	if(!passed)
		log(LogLevel::WARNING, "inject_test: actors {}/{} failed injection check", a1[SK::actor_name].value_or("?"),
			a2[SK::actor_name].value_or("?"));
	return !passed; // true = need re-assignment
}
}
