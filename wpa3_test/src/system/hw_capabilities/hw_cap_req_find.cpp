#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <vector>
#include <sys/types.h>
#include <sys/wait.h>
#include <random>
#include "system/hw_capabilities.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"

namespace wpa3_tester{
using namespace std;
using namespace filesystem;

// ---------------------- BACKTRACKING ------------------------ Map of (RuleKey -> OptionKey)

bool hw_capabilities::findSolution(
    const vector<string> &ruleKeys,
    const size_t ruleIdx,
    const ActorCMap &rules,
    const vector<ActorPtr> &options,
    unordered_set<size_t> &usedOptions,
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

        if(findSolution(ruleKeys, ruleIdx + 1, rules, options, usedOptions, currentAssignment)) return true;

        usedOptions.erase(i);
        currentAssignment.erase(actor_name);
    }
    return false;
}

ActorMap hw_capabilities::check_req_options(const ActorCMap &rules, const vector<ActorPtr> &options){
    vector<string> ruleKeys;
    for(const auto &key: rules | views::keys) ruleKeys.push_back(key);

    ActorMap result;
    if(unordered_set<size_t> usedOptions; findSolution(ruleKeys, 0, rules, options, usedOptions, result)){
        log(LogLevel::DEBUG, "Solved!");
        for(auto const &[r, o]: result) log(LogLevel::DEBUG, "Rule " + r + " -> option " + o->to_str());
        return result;
    }

    Actor_config::print_ActorCMap("Actor rules", rules);
    Actor_config::print_ActorCMap("Actor options", options);

    throw req_err("Not found valid requirements");
}
}