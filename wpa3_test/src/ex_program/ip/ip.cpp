#include "ex_program/ip/ip.h"

#include "system/hw_capabilities.h"

namespace wpa3_tester{
    using namespace std;
    void set_ip(RunStatus& run_status, const string &actor_name){
        const auto netns_client = run_status.config["actors"][actor_name]["netns"].get<string>();
        hw_capabilities::run_cmd({
            "sudo","ip", "addr","add",
            run_status.config["actors"][actor_name]["ip_addr"].get<string>() + "/24",
            "dev",run_status.get_actor(actor_name)["iface"]
        }, netns_client);
    }
}
