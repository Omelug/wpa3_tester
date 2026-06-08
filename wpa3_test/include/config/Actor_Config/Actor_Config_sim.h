#pragma once
#include "Actor_config.h"

namespace wpa3_tester{

class Actor_Config_sim : public Actor_config{
public:
    Actor_Config_sim()                                  : Actor_config()  { set(SK::source, "simulation"); }
    explicit Actor_Config_sim(const nlohmann::json &j)  : Actor_config(j, "simulation") {}
	explicit Actor_Config_sim(const Actor_config &o)    : Actor_config(o) { set(SK::source, "simulation"); }

    void setup_actor(const nlohmann::json &config, const ActorPtr &real_actor) override;
};

}
