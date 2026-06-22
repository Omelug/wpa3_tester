#pragma once
#include <filesystem>
#include <nlohmann/json.hpp>
#include "attacks/two_iface/TwoIface.h"
#include "config/Actor_Config/Actor_Config_sim.h"
#include "logger/error_log.h"

namespace wpa3_tester {

// Concrete stub: redirects cache to temp dir and records run() calls.
struct StubTwoIface : TwoIface {
    nlohmann::json run_result = {{"ok", true}};
    int            run_count  = 0;

    explicit StubTwoIface(const std::string &name)
    : TwoIface({{SK::driver_name, SK::permanent_mac}, {}}, name) {}

    nlohmann::json run(const ActorPtr &, const ActorPtr &) override {
        ++run_count;
        return run_result;
    }

    std::filesystem::path cache_folder() const override {
        return std::filesystem::temp_directory_path() / "stub_two_iface" / cache_name;
    }

    using TwoIface::make_cache_key;
    using TwoIface::lookup_cache;
    using TwoIface::write_cache;
    using TwoIface::cache_path;
};

inline ActorPtr make_stub_actor(const std::string &driver, const std::string &mac){
    const auto ac = std::make_shared<Actor_Config_sim>();
    ac->set(SK::driver_name, driver);
    ac->set(SK::permanent_mac, mac);
    return ActorPtr(ac);
}

// RAII fixture: fresh temp cache dir per test case.
struct TwoIfaceCacheFixture {
    StubTwoIface iface{"test_two_iface_cache_unit"};
    ActorPtr a1 = make_stub_actor("ath9k",   "aa:bb:cc:dd:ee:01");
    ActorPtr a2 = make_stub_actor("mt76x2u", "aa:bb:cc:dd:ee:02");

    TwoIfaceCacheFixture()  { std::filesystem::remove_all(iface.cache_path().parent_path()); }
    ~TwoIfaceCacheFixture() { std::filesystem::remove_all(iface.cache_path().parent_path()); }
};

}
