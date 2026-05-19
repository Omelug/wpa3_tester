#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "config/actor_keys.h"
#include "config/ActorPtr.h"

namespace wpa3_tester {

enum CacheBehave {
    throw_on_miss,
    run_on_miss,
    force_run,
};


class TwoIface {
public:

	ParamFilter     cache_id;
    std::string cache_name;

    TwoIface(ParamFilter id, std::string name);
    virtual ~TwoIface() = default;

    // Run the test; returns json result for saving
    virtual nlohmann::json run(const ActorPtr &a1, const ActorPtr &a2) = 0;

    // Returns {result, from_cache} where from_cache=true means the result was loaded from cache.
    std::pair<nlohmann::json, bool> validate(const ActorPtr &a1, const ActorPtr &a2,
                                             CacheBehave behave = {});

protected:
    [[nodiscard]] std::string make_cache_key(const ActorPtr &a1, const ActorPtr &a2) const;
    [[nodiscard]] std::optional<nlohmann::json> lookup_cache(const std::string &key) const;
    void write_cache(const std::string &key, const nlohmann::json &result) const;
	std::filesystem::path cache_folder() const;
	[[nodiscard]] std::filesystem::path cache_path() const;
	[[nodiscard]] nlohmann::json make_selection(const ActorPtr &a) const;
};

}
