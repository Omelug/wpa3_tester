#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "config/RunStatus.h"
#include "logger/log.h"
#include "observer/tshark_wrapper.h"
#include "setup/program.h"
#include "system/hw_capabilities.h"
#include "system/firmware/ath9k_htc.h"

using namespace std;
using namespace Tins;

namespace wpa3_tester::ath_masker_test{
    void setup_attack(RunStatus &rs){
        program::start(rs, "access_point");
        rs.process_manager.wait_for("access_point", "AP-ENABLED", chrono::seconds(40));
    }

    void run_attack(RunStatus &rs){
        rs.start_observers();
        const int test_count = rs.config.at("attack_config").at("test_mac_count").get<int>();
        const auto att = rs.get_actor("attacker");
        const auto ap = rs.get_actor("access_point");

        const NetworkInterface iface(att["iface"]);
        PacketSender sender(iface);

        for (int i = 0; i < test_count; ++i){
            auto ath_mac = firmware::get_random_ath_masker_mac(att["mac"]);

            Dot11ProbeRequest probe;
            probe.addr1(HWAddress<6>("ff:ff:ff:ff:ff:ff"));
            probe.addr2(ath_mac);
            probe.addr3(ap["mac"]);
            probe.ssid(""); //TODO add essid for clear filtering
            probe.supported_rates({ 1.0f, 2.0f, 5.5f, 11.0f });
            RadioTap radiotap{};
            const int freq_mhz = hw_capabilities::channel_to_freq(stoi(ap["channel"]));
            radiotap.channel(freq_mhz, RadioTap::OFDM);
            radiotap.inner_pdu(probe);
            radiotap.flags(RadioTap::FCS);

            try {
                sender.send(radiotap, iface);
            } catch (const pcap_error& e) {
                log(LogLevel::ERROR, "PCAP Error: %s", e.what());
            } catch (const std::exception& e) {
                log(LogLevel::ERROR, "General Error: %s", e.what());
            }

            this_thread::sleep_for(chrono::milliseconds(10));
        }
        this_thread::sleep_for(chrono::seconds(10));
    }

    void stats(const RunStatus &rs){
        observer::generate_time_series_retry_graph(rs, "attacker");
    }
}
