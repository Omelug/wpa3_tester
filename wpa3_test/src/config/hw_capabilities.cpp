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

// ---------------------- BACKTRACKING ------------------------// RuleKey -> OptionKey

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
    const Config& currentRuleReq = rules.at(currentRuleKey);

    for (auto const& [optKey, optConfig] : options) {
        if (!usedOptions.contains(optKey) &&
            currentRuleReq.matches(optConfig))
        {

            usedOptions.insert(optKey);
            currentAssignment[currentRuleKey] = optKey;

            if (findSolution(ruleKeys, ruleIdx + 1, rules, options, usedOptions, currentAssignment)) {
                return true; // valid result found -> return true up
            }

            usedOptions.erase(optKey);
            currentAssignment.erase(currentRuleKey);
        }
    }
    return false; // not valid options for this
    //TODO
    return false;
}

void hw_capabilities::check_req_options(ActorCMap& rules, const ActorCMap& options) {
    vector<string> ruleKeys;
    for (const auto &k: rules | views::keys) ruleKeys.push_back(k);

    set<string> usedOptions;
    AssignmentMap result;

    if (findSolution(ruleKeys, 0, rules, options, usedOptions, result)) {
        log(LogLevel::DEBUG,"Solved!");
        for (auto const& [r, o] : result) {
            log(LogLevel::DEBUG,"Rule {} -> option {}", r.c_str(), o.c_str());
        }
    } else {
        throw req_error("Not found valid requirements");
    }
}*/