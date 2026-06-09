#pragma once
#include "attacks/two_iface/TwoIface.h"

namespace wpa3_tester {

class TwoIfaceInject : public TwoIface {
public:
    TwoIfaceInject();
    nlohmann::json run(const ActorPtr &t, const ActorPtr &r) override;
    // Returns true if result was loaded from cache (actors may need re-assignment)
    static bool run_check(const ActorPtr &a1, const ActorPtr &a2, CacheBehave behave, const std::string &injection_key);
};

}
