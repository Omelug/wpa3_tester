#pragma once

#include <set>
#include <string>
#include <vector>

#include "RunStatus.h"

class hw_capabilities {
public:
    static void ensure_iw_cached();
    static std::string run_command(const std::string &cmd);
    static std::string get_iw_cache();
    static std::string get_phy_from_iface(const std::string &iface);
    static void reset();
    static bool findSolution(
        const std::vector<std::string>& ruleKeys,
        size_t ruleIdx,
        const ActorCMap& rules,
        const ActorCMap& options,
        std::set<std::string>& usedOptions,
        AssignmentMap& currentAssignment
    );

    static AssignmentMap check_req_options(ActorCMap& rules, const ActorCMap& options);
};
