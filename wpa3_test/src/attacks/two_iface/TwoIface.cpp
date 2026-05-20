#include "attacks/two_iface/TwoIface.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include <fstream>

namespace wpa3_tester{
using namespace std;
using namespace filesystem;
using nlohmann::json;

// ----- TwoIface base
TwoIface::TwoIface(ParamFilter id, string name)
: cache_id(std::move(id)), cache_name(std::move(name)){}

pair<json, bool> TwoIface::validate(const ActorPtr &a1, const ActorPtr &a2, const CacheBehave behave){
	const string key = make_cache_key(a1, a2);

	if(behave != force_run){
		const auto cached = lookup_cache(key);
		if(cached.has_value()){
			log(LogLevel::WARNING, "Found in cache");
			return {*cached, true};
		}
		if(behave == throw_on_miss) throw req_err("ERROR not found in cache " + cache_name);
	}

	const json result = run(a1, a2);

	const auto existing = lookup_cache(key);
	if(existing.has_value() && *existing != result){
		log(LogLevel::WARNING, "TwoIface cache '{}': result changed for key '{}'", cache_name, key);
	}

	write_cache(key, result);
	return {result, false};
}

string TwoIface::make_cache_key(const ActorPtr &a1, const ActorPtr &a2) const{
	return a1->to_str(&cache_id) + "|" + a2->to_str(&cache_id);
}

optional<json> TwoIface::lookup_cache(const string &key) const{
	const path cp = cache_path();
	if(!exists(cp)) return nullopt;

	ifstream ifs(cp);
	string line;
	while(getline(ifs, line)){
		if(line.empty()) continue;
		const auto sep = line.find('\t');
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
			const auto sep = line.find('\t');
			if(sep != string::npos && line.substr(0, sep) == key){
				lines.push_back(key + '\t' + result.dump());
				found = true;
			} else{
				lines.push_back(line);
			}
		}
	}
	if(!found) lines.push_back(key + '\t' + result.dump());

	ofstream ofs(cp, ios::out | ios::trunc);
	for(const auto &l: lines) ofs << l << "\n";
}

path TwoIface::cache_folder() const{
	return path(PROJECT_ROOT_DIR).parent_path() / "data" / "cache" / "two_iface" / cache_name;
}

path TwoIface::cache_path() const{
	return cache_folder() /  "cache.txt";
}

json TwoIface::make_selection(const ActorPtr &a) const {
	auto sel = a->to_json(&cache_id)["selection"];
	sel["channel"] = "11"; //FIXME hardcoded, add to two_iface validator cant be in config
	return sel;
}

}
