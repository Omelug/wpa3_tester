#include "config/Actor_Config/Actor_config.h"
#include <sstream>
#include "config/Actor_Config/Actor_Config_external.h"
#include "config/Actor_Config/Actor_Config_internal.h"
#include "config/Actor_Config/Actor_Config_sim.h"
#include "config/Actor_Config/actor_keys.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "logger/error_log.h"
#include "system/hw_capabilities.h"

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

Actor_config::Actor_config(const json &j, string source) {
	if(!source.empty()) set(SK::source, source);
	if(j.contains("selection") && j.at("selection").is_object()){
		const auto &sel = j.at("selection");

		for(const auto k : sk_values()){
			const auto name = string(sk_name(k));
			if(!sel.contains(name)) continue;
			if(sel[name].is_string()){
				this->set(k, sel[name].get<string>());
			}else if(sel[name].is_number()){
				this->set(k, to_string(sel[name].get<int>()));
			}else if(sel[name].is_array() && k == SK::driver_name){
				string joined;
				for(const auto &v : sel[name]){
					if(!joined.empty()) joined += '|';
					joined += v.get<string>();
				}
				this->set(k, joined);
			}
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
		//const auto name = string(sk_name(SK::mac));
		//if(!this->is_WB()) this->set(SK::mac, sel[name].get<string>());
	}

	if(j.contains("netns"))  set(SK::netns, j.at("netns").get<string>());
	if(j.contains("source")) set(SK::source, j.at("source").get<string>());
}

Actor_config::~Actor_config() {
	if(conn && conn.use_count() == 1)
		conn->disconnect();
}

bool Actor_config::matches(const Actor_config &offer) const {
	for(const auto k : sk_values()){
		const auto &required = (*this)[k];
		if(!required.has_value()) continue;
		const auto &offered  = offer[k];
		if(!offered.has_value()) continue;
		if(k == SK::driver_name && required->contains('|')){
			bool any = false;
			stringstream ss(*required);
			string tok;
			while(getline(ss, tok, '|')) if(tok == *offered){ any = true; break; }
			if(!any) return false;
		} else {
			if(required != offered) return false;
		}
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
			throw run_err(
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
			throw run_err(
				"Actor_config conflict on bool key '" + string(bk_name(k)) + "'");
		}
	}
	return *this;
}

void Actor_config::set(const SK key, const optional<string> &new_value){
	if((key == SK::mac || key == SK::permanent_mac) && new_value.has_value() ){
		string mac_lower = new_value.value();
		ranges::transform(mac_lower, mac_lower.begin(), [](const unsigned char c){ return tolower(c); });
		(*this)[key] = mac_lower;
		return;
	}
	(*this)[key] = new_value;
}

void Actor_config::set(const BK key, const optional<bool> &new_value){
	(*this)[key] = new_value;
}

optional<string>& Actor_config::operator[](SK key) {
	//driver
	if(key == SK::driver_name) return _driver.driver_name;
	if(key == SK::driver_hash) return _driver.driver_hash;
	if(key == SK::module_hash) return _driver.module_hash;

	return str_vals[static_cast<size_t>(key)];
}

const optional<string>& Actor_config::operator[](SK key) const {
	//driver
	if(key == SK::driver_name) return _driver.driver_name;
	if(key == SK::driver_hash) return _driver.driver_hash;
	if(key == SK::module_hash) return _driver.module_hash;

	return str_vals[static_cast<size_t>(key)];
}

optional<bool>& Actor_config::operator[](BK key) {
	return bool_vals[static_cast<size_t>(key)];
}

const optional<bool>& Actor_config::operator[](BK key) const {
	return bool_vals[static_cast<size_t>(key)];
}

string Actor_config::get(const SK key) const {
	const auto &v = (*this)[key];
	if(!v.has_value())
		throw config_err("Actor_config: key '" + string(sk_name(key)) + "' has no value");
	return *v;
}

bool Actor_config::get(const BK key) const {
	const auto &v = (*this)[key];
	if(!v.has_value())
		throw config_err("Actor_config: bool key '" + string(bk_name(key)) + "' has no value");
	return *v;
}

string Actor_config::get_or(const SK key, string default_val) const {
	const auto &v = (*this)[key];
	return v.value_or(std::move(default_val));
}

bool Actor_config::get_or(const BK key, const bool default_val) const {
	const auto &v = (*this)[key];
	return v.value_or(default_val);
}

string Actor_config::to_str(const ParamFilter *filter) const {
	string result;

	bool first = true;
	const auto visit_sk = [&](SK k){
		const auto &v = (*this)[k];
		if(!v.has_value()) return;
		if(!first) result += ", ";
		result += string(sk_name(k)) + "=" + *v;
		first = false;
	};
	if(filter) for(const SK k : filter->first)  visit_sk(k);
	else       for(const SK k : sk_values())    visit_sk(k);

	vector<string> conds;
	const auto visit_bk = [&](BK k){
		const auto &v = (*this)[k];
		if(!v.has_value()) return;
		conds.push_back(*v ? string(bk_name(k)) : "!" + string(bk_name(k)));
	};
	if(filter) for(const BK k : filter->second) visit_bk(k);
	else       for(const BK k : bk_values())    visit_bk(k);

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

json Actor_config::to_json(const ParamFilter *filter) const {
	json sel = json::object();

	const auto visit_sk = [&](const SK k){
		if(k == SK::netns || k == SK::source) return;
		const auto &v = (*this)[k];
		if(v.has_value()) sel[string(sk_name(k))] = *v;
	};
	if(filter) for(const SK k : filter->first)  visit_sk(k);
	else       for(const SK k : sk_values())    visit_sk(k);

	json conditions = json::array();
	const auto visit_bk = [&](BK k){
		const auto &v = (*this)[k];
		if(!v.has_value()) return;
		auto name = string(bk_name(k));
		conditions.push_back(*v ? name : "!" + name);
	};
	if(filter) for(const BK k : filter->second) visit_bk(k);
	else       for(const BK k : bk_values())    visit_bk(k);

	if(!conditions.empty())
		sel["condition"] = conditions;

	json result = json::object();
	result["selection"] = sel;

	if(!filter){
		if((*this)[SK::netns].has_value())  result["netns"]  = *(*this)[SK::netns];
		if((*this)[SK::source].has_value()) result["source"] = *(*this)[SK::source];
	}

	return result;
}

json Actor_config::hw_info_caps_to_flat_json() const {
	json j = json::object();
	for(const auto sk : sk_values()){
		if(!HwInfo::is_hw_info(sk)) continue;
		const auto &v = (*this)[sk];
		if(v.has_value())
			j[string(sk_name(sk))] = *v;
	}
	for(const auto bk : bk_values()){
		if(!HwInfo::is_hw_info(bk)) continue;
		const auto &v = (*this)[bk];
		if(v.has_value())
			j[string(bk_name(bk))] = *v;
	}
	return j;
}

void Actor_config::caps_from_flat_json(const json &j) {
	for(const auto k : bk_values()){
		if(!HwInfo::is_hw_info(k)) continue;
		const auto name = string(bk_name(k));
		if(j.contains(name) && j.at(name).is_boolean())
			(*this)[k] = j.at(name).get<bool>();
	}
}

void Actor_config::print_ActorCMap(const string &title, const vector<ActorPtr> &actors) {
	cout << title << ":\n";
	for(size_t i = 0; i < actors.size(); ++i)
		cout << "[" << i << "] " << actors[i]->to_str() << "\n";
	cout << flush;
}

void Actor_config::print_ActorCMap(const string &title, const ActorCMap& actors) {
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
	return get(SK::source) == "simulation" || get(SK::source) == "internal" || is_external_WB();
}

bool Actor_config::is_external_WB() const {
	return get(SK::source) == "external" &&
			((*this)[SK::whitebox_host].has_value() || (*this)[SK::whitebox_ip].has_value());
}

bool Actor_config::monitor_needed() const{
	return get_or(BK::monitor, false) ||
			get_or(BK::active_monitor, false) ||
			get_or(BK::control_monitor, false) ||
			get_or(BK::injection_selftest, false);
}

shared_ptr<Actor_config> Actor_config::create(const json &j){
	const auto source = j.at("source").get<string>();
	if(source == "simulation") return make_shared<Actor_Config_sim>(j);
	if(source == "external")   return make_shared<Actor_Config_external>(j);
	return make_shared<Actor_Config_internal>(j);
}

}
