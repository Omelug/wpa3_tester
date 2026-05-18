#pragma once
#include "attacks/two_iface/TwoIface.h"

namespace wpa3_tester {

class TwoIfaceInject : public TwoIface {
public:
    TwoIfaceInject();
    nlohmann::json run(const ActorPtr &a1, const ActorPtr &a2) override;
    // Returns true if actors need hardware re-assignment (test failed)
    static bool run_check(const ActorPtr &a1, const ActorPtr &a2);
};

} // namespace wpa3_tester
