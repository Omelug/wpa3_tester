#pragma once

#include <set>
#include <string>
#include <vector>

#include "RunStatus.h"


class hw_capabilities {
    using AssignmentMap = map<string, string>;

    /*std::string run_command(const std::string &cmd);
    std::string get_phy_from_iface(const std::string &iface);
    void reset();
    void ensure_iw_cached();
    */
    static bool findSolution(
        const std::vector<std::string>& ruleKeys,
        size_t ruleIdx,
        const ActorCMap& rules,
        const ActorCMap& options,
        set<string>& usedOptions,
        AssignmentMap& currentAssignment
    );

    static void check_req_options(ActorCMap& rules, const ActorCMap& options);
};
