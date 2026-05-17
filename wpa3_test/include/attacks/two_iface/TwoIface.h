#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "config/actor_keys.h"
#include "config/ActorPtr.h"

namespace wpa3_tester {

struct CacheBehave {
    bool throw_on_miss = false;
    bool run_on_miss   = true;
    bool force_run     = false;
};

// Identifies which actor fields form the cache key for a two-iface test
using CacheId = std::pair<std::vector<SK>, std::vector<BK>>;

class TwoIface {
public:

	CacheId     cache_id;
    std::string cache_name;

    TwoIface(CacheId id, std::string name);
    virtual ~TwoIface() = default;

    // Run the test; returns json result for saving
    virtual nlohmann::json run(const ActorPtr &a1, const ActorPtr &a2) = 0;

    // Look up cache, run if needed per behave policy, log on result change
    nlohmann::json validate(const ActorPtr &a1, const ActorPtr &a2,
                            CacheBehave behave = {});

protected:
    [[nodiscard]] std::string make_cache_key(const ActorPtr &a1, const ActorPtr &a2) const;
    [[nodiscard]] std::optional<nlohmann::json> lookup_cache(const std::string &key) const;
    void write_cache(const std::string &key, const nlohmann::json &result) const;
    [[nodiscard]] std::filesystem::path cache_path() const;
};

// -----------------
class TwoIfaceActive : public TwoIface {
public:
    TwoIfaceActive();
    nlohmann::json run(const ActorPtr &a1, const ActorPtr &a2) override;
    // Returns true if actors need hardware re-assignment (test failed)
    static bool run_check(const ActorPtr &a1, const ActorPtr &a2);
};

// -----------------
class TwoIfaceInject : public TwoIface {
public:
    TwoIfaceInject();
    nlohmann::json run(const ActorPtr &a1, const ActorPtr &a2) override;
    // Returns true if actors need hardware re-assignment (test failed)
    static bool run_check(const ActorPtr &a1, const ActorPtr &a2);
};

} // namespace wpa3_tester
