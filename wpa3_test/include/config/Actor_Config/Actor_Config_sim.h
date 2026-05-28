#pragma once
#include "Actor_config.h"

namespace wpa3_tester{

class Actor_Config_sim : public Actor_config{
public:
    using Actor_config::Actor_config;
    void setup_actor(const nlohmann::json &config, const ActorPtr &real_actor) override;
};

}
