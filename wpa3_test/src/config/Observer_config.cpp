#include "config/Observer_config.h"

#include "config/RunStatus.h"
#include "observer/mausezahn_wrapper.h"
#include "observer/resource_checker.h"
#include "observer/tcpdump_wrapper.h"
#include "observer/tshark_wrapper.h"

using namespace std;
namespace wpa3_tester::observer{
    void Observer_config::start(RunStatus &rs) const{
        const auto program = observer_config.at("program").get<string>();
        const auto actor_name = observer_config.at("actor").get<string>();
        const auto program_config = observer_config.at("program_config");
        if(program == "tshark"){
            const string filter = program_config.value("filter", "");
            start_tshark(rs, actor_name, filter);
            return;
        }
        if(program == "tcpdump"){
            const string filter = program_config.value("filter", "");
            start_tcpdump(rs, actor_name, filter);
            return;
        }

        if(program == "musezahn"){
            const auto target_actor = program_config.at("target_actor").get<string>();
            start_musezahn(rs, actor_name+"_mz_gen", actor_name, target_actor);
            return;
        }

        if(program == "resource_checker"){
            const auto interval = program_config.at("interval").get<int>();
            start_resource_monitoring(rs, actor_name, interval);
            return;
        }
        throw runtime_error("Invalid observer program: "+program);
    }

    string Observer_config::to_str() const {
        return "Observer: " + observer_name;
    }
}
