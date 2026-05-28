#pragma once
#include "Actor_config.h"

namespace wpa3_tester{

class Actor_Config_external : public Actor_config{
public:
    using Actor_config::Actor_config;
    explicit Actor_Config_external(const Actor_config &other) : Actor_config(other) {}
    void setup_actor(const nlohmann::json &config, const ActorPtr &real_actor) override;
};

}
