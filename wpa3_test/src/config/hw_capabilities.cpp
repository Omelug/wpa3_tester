#include "../../include/config/hw_capabilities.h"

#include <string>
#include <cstdio>
#include <map>
#include <set>
#include <vector>

#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"

using namespace std;
/*
void hw_capabilities::ensure_iw_cached() {
    if (iw_cache.has_value()) {
        return; // already cached
    }
    const string cmd = "iw phy";
    iw_cache = run_command(cmd);
}

string hw_capabilities::run_command(const string &cmd) {
    array<char, 4096> buf{};
    string result;

    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe) {return {};}

    while (fgets(buf.data(), buf.size(), pipe) != nullptr) {
        result.append(buf.data());
    }
    pclose(pipe);
    return result;
}

string hw_capabilities::get_phy_from_iface(const string &iface) {
    string out = run_command("iw dev");
    if (out.empty()) {return {};}

    string current_phy;
    const string phy_prefix = "phy#";
    const string iface_prefix = "\tInterface ";

    size_t pos = 0;
    while (pos < out.size()) {
        size_t end = out.find('\n', pos);
        if (end == string::npos) end = out.size();

        string line = out.substr(pos, end - pos);
        if (line.rfind(phy_prefix, 0) == 0) {
            current_phy = line.substr(phy_prefix.size());
        } else if (line.rfind(iface_prefix, 0) == 0) {
            string name = line.substr(iface_prefix.size());
            if (name == iface) {return current_phy;}
        }
        pos = end + 1;
    }
    return {};
}

void hw_capabilities::reset() {
    iw_cache = nullptr;
}

// ---------------------- BACKTRACKING ------------------------ Map of (RuleKey -> OptionKey)
*/
bool hw_capabilities::findSolution(
    const vector<string>& ruleKeys,
    const size_t ruleIdx,
    const ActorCMap& rules,
    const ActorCMap& options,
    set<string>& usedOptions,
    AssignmentMap& currentAssignment
){
    // all set? -> solution found
    if (ruleIdx == ruleKeys.size()) {
        return true;
    }

    const string& currentRuleKey = ruleKeys[ruleIdx];
    const auto &ruleIt = rules.find(currentRuleKey);
    if (ruleIt == rules.end() || !ruleIt->second) {
        throw config_error("Missing rule actor config for key: %s", currentRuleKey.c_str());
    }
    Actor_config& currentRuleReq = *ruleIt->second;

    for (auto const& [optKey, optConfigPtr] : options) {
        if (!optConfigPtr) {
            continue; // skip empty
        }
        if (usedOptions.contains(optKey)) {
            continue; // already used this option
        }

        Actor_config& optConfig = *optConfigPtr;
        if (!currentRuleReq.matches(optConfig)) {
            continue;
        }

        // choose this option for current rule
        usedOptions.insert(optKey);
        currentAssignment[currentRuleKey] = optKey;

        if (findSolution(ruleKeys, ruleIdx + 1, rules, options, usedOptions, currentAssignment)) {
            return true; // valid assignment found
        }

        // backtrack
        usedOptions.erase(optKey);
        currentAssignment.erase(currentRuleKey);
    }

    return false; // no valid option for this rule
}

void hw_capabilities::check_req_options(ActorCMap& rules, const ActorCMap& options) {
    vector<string> ruleKeys;
    for (const auto &key: rules | views::keys) ruleKeys.push_back(key);

    AssignmentMap result;
    if (set<string> usedOptions;
        findSolution(ruleKeys, 0, rules, options, usedOptions, result)) {
        log(LogLevel::DEBUG, "Solved!");
        for (auto const& [r, o] : result) {
            log(LogLevel::DEBUG, "Rule %s -> option %s", r.c_str(), o.c_str());
        }
    } else {
        throw req_error("Not found valid requirements");
    }
}