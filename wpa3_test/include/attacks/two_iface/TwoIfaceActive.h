#pragma once
#include "attacks/two_iface/TwoIface.h"

namespace wpa3_tester {
class TwoIfaceActive: public TwoIface {
public:
	TwoIfaceActive();
	nlohmann::json run(const ActorPtr &a1, const ActorPtr &a2) override;
	// returns true if result was loaded from cache
	static bool run_check(const ActorPtr &a1, const ActorPtr &a2, CacheBehave behave);
	static void backfill_cache(const ActorPtr &a1, const ActorPtr &a2, const nlohmann::json &result);
	// search cache ignoring BK flags:
	// return nullopt=no success found
	// return false=works without active_monitor
	// return true=needs active_monitor
	static std::optional<bool> find_cache_needs_active(const ActorPtr &acker);
};
}
