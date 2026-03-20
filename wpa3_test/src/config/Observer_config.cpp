#include "config/Observer_config.h"

#include "config/RunStatus.h"
#include "observer/mausezahn_wrapper.h"
#include "observer/tcpdump_wrapper.h"
#include "observer/tshark_wrapper.h"

using namespace std;
namespace wpa3_tester::observer{
    int Observer_config::start(RunStatus &rs) const {
        const auto program = observer_config.at("program").get<string>();
        const auto actor_name = observer_config.at("actor").get<string>();
        if(program == "tshark"){
            const auto filter = observer_config.at("filter").get<string>();
            start_tshark(rs, actor_name, filter);
        }
        if(program == "tcpdump"){
            const auto filter = observer_config.at("filter").get<string>();
            start_tcpdump(rs, actor_name, filter);
        }
        if(program == "musezahn"){
            const auto target_actor = observer_config.at("target_actor").get<string>();
            start_musezahn(rs,actor_name+"_mz_gen", actor_name, target_actor);
        }
        throw runtime_error("Invalid observer program");
    }

    string Observer_config::to_str() const {
        return "Observer: " + observer_name;
    }
}
