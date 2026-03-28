#include "config/RunStatus.h"
#include "logger/log.h"
#include "setup/program.h"
#include "system/ip.h"

using namespace std;

namespace wpa3_tester::components{
    void setup_AP(RunStatus& rs,const string& actor_name){
        program::start(rs, actor_name);
        rs.process_manager.wait_for(actor_name, "AP-ENABLED", chrono::seconds(40));
        log(LogLevel::INFO, actor_name+" is running");
        ip::set_ip(rs, actor_name);
    }

    void setup_STA(RunStatus& rs,const string& actor_name){
        program::start(rs, actor_name);
        rs.process_manager.wait_for("client", "Successfully initialized wpa_supplicant", chrono::seconds(10));
        ip::set_ip(rs, "client");
    }

    void client_ap_attacker_setup(RunStatus& rs){

        if (rs.get_actor("attacker")["source"] != "internal" || rs.get_actor("client")["source"] != "internal") {
            throw runtime_error("only internal actors are supported");
        }

        setup_AP(rs, "access_point");
        setup_STA(rs, "client");

        rs.process_manager.wait_for("client", "EVENT-CONNECTED", chrono::seconds(60));
        rs.process_manager.wait_for("access_point", "EAPOL-4WAY-HS-COMPLETED", chrono::seconds(40));
        log(LogLevel::INFO, "client is connected");
    }

    void client_ap_attacker_setup_enterprise(RunStatus& rs){

        if (rs.get_actor("attacker")["source"] != "internal" || rs.get_actor("client")["source"] != "internal") {
            throw runtime_error("only internal actors are supported");
        }

        if(rs.get_actor("access_point")->is_WB()) setup_AP(rs, "access_point");
        setup_STA(rs, "client");

        rs.process_manager.wait_for("client", "EVENT-CONNECTED", chrono::seconds(40));
        //if(rs.get_actor("access_point")->is_WB()){
        //    rs.process_manager.wait_for("access_point", "AP-STA-CONNECTED", chrono::seconds(40));
        //} // ony check, not
        log(LogLevel::INFO, "client is connected");
    }
}
