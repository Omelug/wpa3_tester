#include "ex_program/ip/ip.h"

#include "observer/observers.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
    using namespace std;
    void set_ip(RunStatus& run_status, const string &actor_name){
        vector<string> command = {"sudo"};
        observer::add_nets(run_status,command, actor_name);
        command.insert(command.end(), {
            "sudo","ip", "addr","add",
            run_status.config["actors"][actor_name]["ip_addr"].get<string>() + "/24",
            "dev",run_status.get_actor(actor_name)["iface"]
        });
        hw_capabilities::run_cmd(command);
    }
}
