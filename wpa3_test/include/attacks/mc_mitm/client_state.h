#pragma once
#include <string>
#include <tins/tins.h>
#include "wifi_util.h"
#include "logger/log.h"

namespace wpa3_tester{
struct NetworkConfig{
    std::string ssid;
    uint8_t real_channel = -1;
    uint8_t rogue_channel = -1;
};

class ClientState{
public:
    enum State{
        Initializing = 0,
        Connecting,
        GotMitm,
        Attack_Started, // start attack -> filter/change
        Attack_Done
    };

    State state = Initializing;
    std::string macaddr;

    using time_point = std::chrono::steady_clock::time_point;
    time_point last_real = std::chrono::steady_clock::now();
    time_point last_rogue = std::chrono::steady_clock::now();
public:
    virtual ~ClientState() = default;

    explicit ClientState(const std::string &mac): macaddr(mac){}

    void reset(){
        state = Initializing;
        last_real = std::chrono::steady_clock::now();
        last_rogue = std::chrono::steady_clock::now();
    }

    void update_state(const State s){
        log(LogLevel::DEBUG, "Client " + macaddr + " moved to state " + state2str(s));
        state = s;
    }

    bool is_state(const State s) const{
        return this->state == s;
    }

    // Returns true if this call actually advanced to GotMitm for the first time.
    bool mark_got_mitm(){
        if(state <= Connecting){
            update_state(GotMitm);
            log(LogLevel::INFO, "Established MitM position against client " + macaddr);
            return true;
        }
        return false;
    }

    // By default, everything is forwarded.
    virtual bool should_forward(const Tins::PDU & /*pkt*/) const{ return true; }
    // By default, frames are not modified.
    virtual void modify_packet(Tins::PDU &pkt) const{}

    void attack_start(){ update_state(Attack_Started); }
private:
    static std::string state2str(const State state){
        static const char *names[] = {
            "Initializing", "Connecting", "GotMitm", "Attack_Started", "Attack_Done"
        };
        return (state < 5) ? names[state] : "Unknown";
    }
};
}