#pragma once
#include <string>
#include <tins/tins.h>
#include "wifi_util.h"
#include "logger/log.h"

namespace wpa3_tester{

    struct NetworkConfig {
        std::string ssid;
        int real_channel  = -1;
        int rogue_channel = -1;
    };

    class ClientState {
    public:
        virtual ~ClientState() = default;

        enum State {
            Initializing = 0,
            Connecting,
            GotMitm,
            Attack_Started,
            Attack_Done
        };

        std::string macaddr;
        State       state      = Initializing;
        double      last_real   = 0.0;
        double      last_rogue  = 0.0;

        explicit ClientState(const std::string& mac) : macaddr(mac) {}

        void update_state(State s) {
            log(LogLevel::DEBUG, "Client " + macaddr + " moved to state " + state2str(s));
            state = s;
        }

        // Returns true if this call actually advanced to GotMitm for the first time.
        bool mark_got_mitm() {
            if (state <= Connecting) {
                update_state(GotMitm);
                log(LogLevel::INFO, "Established MitM position against client " + macaddr);
                return true;
            }
            return false;
        }

        virtual bool should_forward(const Tins::PDU& /*pkt*/) const { return true; }
        virtual Tins::PDU* modify_packet(Tins::PDU* pkt) const { return pkt; }

    private:
        static std::string state2str(State s) {
            static const char* names[] = {
                "Initializing", "Connecting", "GotMitm", "Attack_Started", "Attack_Done"
            };
            return (s < 5) ? names[s] : "Unknown";
        }
    };
}