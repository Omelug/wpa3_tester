#include <cstdlib>
#include <random>
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

	Actor_config &currentRuleReq = *ruleIt->second;

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
	Actor_config &req = *ruleIt->second;
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

	throw req_err("Not found valid requirements");
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
}