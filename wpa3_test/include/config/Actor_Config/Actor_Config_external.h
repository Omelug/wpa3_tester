#pragma once
#include "Actor_config.h"

namespace wpa3_tester{

class Actor_Config_external : public Actor_config{
public:
    Actor_Config_external()                                  : Actor_config()  { set(SK::source, "external"); }
    explicit Actor_Config_external(const nlohmann::json &j)  : Actor_config(j) { set(SK::source, "external"); }
	explicit Actor_Config_external(const Actor_config &o)    : Actor_config(o) { set(SK::source, "external"); }
    void setup_actor(const nlohmann::json &config, const ActorPtr &real_actor) override;
};

}
