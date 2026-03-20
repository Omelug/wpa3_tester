#include "setup/program.h"

#include "ex_program/external_actors/ExternalConn.h"
#include "ex_program/hostapd/hostpad.h"
#include "logger/error_log.h"

using namespace std;
namespace wpa3_tester{
    void program::start(RunStatus &rs, const string &actor_name){
        auto setup = rs.config.at("actors").at(actor_name).at("setup");
        const auto program = setup.at("program").get<string>();
        const auto actor = rs.get_actor(actor_name);
        if(program == "hostapd"){
            if(actor["source"] != "internal") throw setup_err(program+" can be only internal");
            hostapd::run_hostapd(rs, actor_name);
        }
        if(program == "wpa_supplicant"){
            if(actor["source"] != "internal") throw setup_err(program+" can be only internal");
            hostapd::run_wpa_supplicant(rs, actor_name);
        }
        if(program == "openwrt"){
            if(actor->conn == nullptr) throw setup_err("openwrt have to have connection");
            actor->conn.get()->logger(rs, actor_name);
            actor->conn.get()->setup_ap(rs, actor);
        }
    }
}

