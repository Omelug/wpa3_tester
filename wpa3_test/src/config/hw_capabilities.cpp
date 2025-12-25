#include "config/hw_capabilities.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"

#include <string>
#include <cstdio>
#include <map>
#include <set>
#include <vector>

using namespace std;

namespace {
    std::string g_iw_cache; // cached output of `iw dev`
}

void hw_capabilities::ensure_iw_cached() {
    if (!g_iw_cache.empty()) {
        return; // already cached
    }
    const string cmd = "iw dev";
    g_iw_cache = run_command(cmd);
}

string hw_capabilities::get_iw_cache() {
    ensure_iw_cached();
    return g_iw_cache;
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
    string out = get_iw_cache();
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
            // strip trailing spaces / CR
            while (!name.empty() && isspace(static_cast<unsigned char>(name.back()))) {
                name.pop_back();
            }
            if (name == iface) {return current_phy;}
        }
        pos = end + 1;
    }
    return {};
}

void hw_capabilities::reset() {
    g_iw_cache = nullptr;
}

// ---------------------- BACKTRACKING ------------------------ Map of (RuleKey -> OptionKey)

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

AssignmentMap hw_capabilities::check_req_options(ActorCMap& rules, const ActorCMap& options) {
    vector<string> ruleKeys;
    for (const auto &key: rules | views::keys) ruleKeys.push_back(key);

    AssignmentMap result;
    if (set<string> usedOptions;
        findSolution(ruleKeys, 0, rules, options, usedOptions, result)) {
        log(LogLevel::DEBUG, "Solved!");
        for (auto const& [r, o] : result) {
            log(LogLevel::DEBUG, "Rule %s -> option %s", r.c_str(), o.c_str());
        }
		return result;
    }
	throw req_error("Not found valid requirements");
}