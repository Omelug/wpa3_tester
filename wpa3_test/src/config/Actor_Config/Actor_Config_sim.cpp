#include "config/Actor_Config/Actor_Config_sim.h"

namespace wpa3_tester{
void Actor_Config_sim::setup_actor(const nlohmann::json &config, const ActorPtr &real_actor){
	Actor_config::setup_actor(config, real_actor);
}
}
