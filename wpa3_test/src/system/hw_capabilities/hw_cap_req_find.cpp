#include <cstdlib>
#include <random>
#include <set>
#include <string>
#include <vector>
#include <sys/types.h>
#include <sys/wait.h>
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;
using namespace filesystem;

// ---------------------- BACKTRACKING ------------------------ Map of (RuleKey -> OptionKey)

bool hw_capabilities::find_solution(const vector<string> &ruleKeys, const size_t ruleIdx, const ActorCMap &rules,
									const vector<ActorPtr> &options, unordered_set<size_t> &usedOptions,
									ActorMap &currentAssignment
){
	if(ruleIdx == ruleKeys.size()) return true;

	const string &actor_name = ruleKeys[ruleIdx];
	const auto &ruleIt = rules.find(actor_name);
	if(ruleIt == rules.end()) throw config_err("Missing rule actor config for actor: " + actor_name);

	const Actor_config &currentRuleReq = *ruleIt->second;

	for(size_t i = 0; i < options.size(); i++){
		if(usedOptions.contains(i)) continue;
		if(!currentRuleReq.matches(*options[i])) continue;

		usedOptions.insert(i);
		currentAssignment.insert_or_assign(actor_name, options[i]);

		if(find_solution(ruleKeys, ruleIdx + 1, rules, options, usedOptions, currentAssignment)) return true;

		usedOptions.erase(i);
		currentAssignment.erase(actor_name);
	}
	return false;
}

void hw_capabilities::find_all_solutions(const vector<string> &ruleKeys, const size_t ruleIdx, const ActorCMap &rules,
										const vector<ActorPtr> &options, unordered_set<size_t> &usedOptions,
										ActorMap &current, vector<ActorMap> &results
){
	if(ruleIdx == ruleKeys.size()){
		results.push_back(current);
		return;
	}
	const string &actor_name = ruleKeys[ruleIdx];
	const auto &ruleIt = rules.find(actor_name);
	if(ruleIt == rules.end()) throw config_err("Missing rule actor config for actor: " + actor_name);
	const Actor_config &req = *ruleIt->second;
	for(size_t i = 0; i < options.size(); i++){
		if(usedOptions.contains(i)) continue;
		if(!req.matches(*options[i])) continue;
		usedOptions.insert(i);
		current.insert_or_assign(actor_name, options[i]);
		find_all_solutions(ruleKeys, ruleIdx + 1, rules, options, usedOptions, current, results);
		usedOptions.erase(i);
		current.erase(actor_name);
	}
}

ActorMap hw_capabilities::check_req_options(const ActorCMap &rules, const vector<ActorPtr> &options){
	vector<string> ruleKeys;
	for(const auto &key: rules | views::keys) ruleKeys.push_back(key);

	ActorMap result;
	if(unordered_set<size_t> usedOptions; find_solution(ruleKeys, 0, rules, options, usedOptions, result)){
		log(LogLevel::DEBUG, "Solved!");
		for(auto const &[r, o]: result) log(LogLevel::DEBUG, "Rule {} -> option {}", r, o->to_str());
		return result;
	}

	Actor_config::print_ActorCMap("Actor rules", rules);
	Actor_config::print_ActorCMap("Actor options", options);
	throw req_err("Not found valid requirements: " + get_heuristic_err_msg(rules, options));
}

vector<ActorMap> hw_capabilities::check_all_req_options(const ActorCMap &rules, const vector<ActorPtr> &options){
	vector<string> ruleKeys;
	for(const auto &key: rules | views::keys) ruleKeys.push_back(key);
	vector<ActorMap> results;
	ActorMap current;
	unordered_set<size_t> used;
	find_all_solutions(ruleKeys, 0, rules, options, used, current, results);
	return results;
}

string hw_capabilities::get_heuristic_err_msg(const ActorCMap &rules, const vector<ActorPtr> &options){
	if(options.size() < rules.size()) return format("not enough interfaces: {} required, {} available", rules.size(),
													options.size());
	string msg;
	for(const auto &[actor_name, req_ptr]: rules){
		const Actor_config &req = *req_ptr;
		bool any_match = false;
		for(const auto &opt: options) if(req.matches(*opt)){
			any_match = true;
			break;
		}
		if(any_match) continue;
		for(const auto k: sk_values()){
			if(k == SK::actor_name || k == SK::channel || k == SK::netns) continue;
			const auto &r = req[k];
			if(!r.has_value()) continue;
			set<string> possible;
			for(const auto &opt: options){
				const auto &o = (*opt)[k];
				if(o.has_value()) possible.insert(*o);
			}
			if(possible.contains(*r)) continue;
			const string kname{sk_name(k)};
			msg += kname;
			msg += " ";
			msg += *r;
			msg += " is required by ";
			msg += actor_name;
			msg += ", possible ";
			msg += kname;
			msg += "s {";
			bool first = true;
			for(const auto &v: possible){
				if(!first) msg += ", ";
				msg += v;
				first = false;
			}
			msg += "}; ";
		}
		for(const auto k: bk_values()){
			const auto &r = req[k];
			if(!r.has_value()) continue;
			set<string> possible;
			for(const auto &opt: options){
				const auto &o = (*opt)[k];
				if(o.has_value()) possible.insert(*o ? "true" : "false");
			}
			const string req_val = *r ? "true" : "false";
			if(possible.contains(req_val)) continue;
			const string kname{bk_name(k)};
			msg += kname;
			msg += " ";
			msg += req_val;
			msg += " is required by ";
			msg += actor_name;
			msg += ", possible ";
			msg += kname;
			msg += "s {";
			bool first = true;
			for(const auto &v: possible){
				if(!first) msg += ", ";
				msg += v;
				first = false;
			}
			msg += "}; ";
		}
	}
	if(msg.empty()) msg = "each actor individually matches some option; conflict is combinatorial";
	return msg;
}
}