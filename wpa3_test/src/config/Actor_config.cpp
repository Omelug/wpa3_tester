#include "config/Actor_config.h"
#include "config/ActorPtr.h"
#include "config/actor_keys.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "logger/error_log.h"

namespace wpa3_tester {
using namespace std;
using json = nlohmann::json;

string Actor_config::operator[](const string &key) const {
	if(const auto k = sk_cast(key); k.has_value()){
		const auto &v = (*this)[*k];
		if(!v.has_value())
			throw config_err("Actor_config: key '" + key + "' has no value");
		return *v;
	}
	throw config_err("Actor_config: unknown string key '" + key + "'");
}

Actor_config::Actor_config(const json &j) {
	if(j.contains("selection") && j.at("selection").is_object()){
		const auto &sel = j.at("selection");

		for(const auto k : sk_values()){
			const auto name = string(sk_name(k));
			if(!sel.contains(name)) continue;
			if(k == SK::mac){
				set_mac(sel[name].get<string>());
				continue;
			}
			if(k == SK::permanent_mac){
				set_permanent_mac(sel[name].get<string>());
				continue;
			}
			if(sel[name].is_string())
				(*this)[k] = sel[name].get<string>();
			else if(sel[name].is_number())
				(*this)[k] = to_string(sel[name].get<int>());
		}

		if(sel.contains("condition") && sel.at("condition").is_array()){
			for(const auto &cond : sel.at("condition")){
				auto raw = cond.get<string>();
				const bool negated = raw.starts_with('!');
				const auto name    = negated ? raw.substr(1) : raw;
				if(const auto k = bk_cast(name); k.has_value())
					(*this)[*k] = !negated;
			}
		}
	}

	if(j.contains("netns"))  (*this)[SK::netns]  = j.at("netns").get<string>();
	if(j.contains("source")) (*this)[SK::source] = j.at("source").get<string>();
}

Actor_config::~Actor_config() {
	if(conn && conn.use_count() == 1)
		conn->disconnect();
}

bool Actor_config::matches(const Actor_config &offer) {
	for(const auto k : sk_values()){
		const auto &required = (*this)[k];
		if(!required.has_value()) continue;
		const auto &offered  = offer[k];
		if(!offered.has_value()) continue;
		if(required != offered) return false;
	}

	for(const auto k : bk_values()){
		const auto &required = (*this)[k];
		if(!required.has_value()) continue;
		const auto &offered  = offer[k];
		if(!offered.has_value()) continue;
		if(required != offered) return false;
	}
	return true;
}

Actor_config &Actor_config::operator+=(const Actor_config &other) {
	for(const auto k : sk_values()){
		const auto &val = other[k];
		if(!val.has_value()) continue;
		auto &mine = (*this)[k];
		if(!mine.has_value()){
			mine = val;
		} else if(mine != val){
			throw runtime_error(
				"Actor_config conflict on key '" + string(sk_name(k)) +
				"': '" + *mine + "' vs '" + *val + "'");
		}
	}

	for(const auto k : bk_values()){
		const auto &val = other[k];
		if(!val.has_value()) continue;
		auto &mine = (*this)[k];
		if(!mine.has_value()){
			mine = val;
		} else if(mine != val){
			throw runtime_error(
				"Actor_config conflict on bool key '" + string(bk_name(k)) + "'");
		}
	}
	return *this;
}

optional<string>& Actor_config::operator[](SK key) {
	return str_vals[static_cast<size_t>(key)];
}

const optional<string>& Actor_config::operator[](SK key) const {
	return str_vals[static_cast<size_t>(key)];
}

optional<bool>& Actor_config::operator[](BK key) {
	return bool_vals[static_cast<size_t>(key)];
}

const optional<bool>& Actor_config::operator[](BK key) const {
	return bool_vals[static_cast<size_t>(key)];
}

string Actor_config::get(SK key) const {
	const auto &v = (*this)[key];
	if(!v.has_value())
		throw config_err("Actor_config: key '" + string(sk_name(key)) + "' has no value");
	return *v;
}

bool Actor_config::get(BK key) const {
	const auto &v = (*this)[key];
	if(!v.has_value())
		throw config_err("Actor_config: bool key '" + string(bk_name(key)) + "' has no value");
	return *v;
}

string Actor_config::to_str() const {
	string result;

	bool first = true;
	for(const auto k : sk_values()){
		const auto &v = (*this)[k];
		if(!v.has_value()) continue;
		if(!first) result += ", ";
		result += string(sk_name(k)) + "=" + *v;
		first = false;
	}

	vector<string> conds;
	for(const auto k : bk_values()){
		const auto &v = (*this)[k];
		if(!v.has_value()) continue;
		conds.push_back(*v ? string(bk_name(k)) : "!" + string(bk_name(k)));
	}

	if(!conds.empty()){
		result += " [";
		for(size_t i = 0; i < conds.size(); ++i){
			if(i > 0) result += ", ";
			result += conds[i];
		}
		result += "]";
	}

	return result;
}

json Actor_config::to_json() const {
	json sel = json::object();

	for(const auto k : sk_values()){
		if(k == SK::netns || k == SK::source) continue;
		const auto &v = (*this)[k];
		if(v.has_value())
			sel[string(sk_name(k))] = *v;
	}

	json conditions = json::array();
	for(const auto k : bk_values()){
		const auto &v = (*this)[k];
		if(!v.has_value()) continue;
		auto name = string(bk_name(k));
		conditions.push_back(*v ? name : "!" + name);
	}
	if(!conditions.empty())
		sel["condition"] = conditions;

	json result = json::object();
	result["selection"] = sel;

	if((*this)[SK::netns].has_value())  result["netns"]  = *(*this)[SK::netns];
	if((*this)[SK::source].has_value()) result["source"] = *(*this)[SK::source];

	return result;
}

void Actor_config::print_ActorCMap(const string &title, const vector<ActorPtr> &actors) {
	cout << title << ":\n";
	for(size_t i = 0; i < actors.size(); ++i)
		cout << "[" << i << "] " << actors[i]->to_str() << "\n";
	cout << flush;
}

void Actor_config::print_ActorCMap(const string &title, ActorCMap actors) {
	cout << title << ":\n";
	for(const auto &[key, actor_ptr]: actors){
		const ActorPtr actor = actor_ptr;
		const auto &host = actor[SK::whitebox_host];
		cout << "[" << key << "] "
				<< (host.has_value() ? *host : "Actor_" + key)
				<< " " << actor->to_str() << "\n";
	}
	cout << flush;
}

bool Actor_config::is_WB() const {
	return (*this)[SK::source].value() == "internal" || is_external_WB();
}

bool Actor_config::is_external_WB() const {
	return (*this)[SK::source].value() == "external" &&
			((*this)[SK::whitebox_host].has_value() || (*this)[SK::whitebox_ip].has_value());
}

}