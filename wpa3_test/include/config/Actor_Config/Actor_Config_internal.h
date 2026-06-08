#pragma once
#include "Actor_config.h"

namespace wpa3_tester{

class Actor_Config_internal : public Actor_config{
public:
    Actor_Config_internal()                                  : Actor_config()  {set(SK::source, "internal");}
    explicit Actor_Config_internal(const nlohmann::json &j)  : Actor_config(j, "internal") {};
	explicit Actor_Config_internal(const Actor_config &o)    : Actor_config(o){};

    void setup_actor(const nlohmann::json &config, const ActorPtr &real_actor) override;
};

}
