#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"
#include <fstream>
#include <unistd.h>
#include <csignal>
#include <tins/sniffer.h>
#include <tins/hw_address.h>

#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "pcap/pcap.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::cookie_guzzler{
optional<dos_helpers::SAEPair> capture_sae_commit(const string &iface, const HWAddress<6> &ap_mac,
                                                  const int timeout_sec, pcap_t *handle
){
    dos_helpers::SAEPair result{};
    char errbuf[PCAP_ERRBUF_SIZE];

    const bool owns_handle = (handle == nullptr);
    if(owns_handle){
        handle = pcap_open_live(iface.c_str(), 2000, 1, 100, errbuf);
        if(!handle) throw runtime_error("pcap_open_live failed: " + string(errbuf));
        pcap_setnonblock(handle, 1, errbuf);
    }

    auto handle_guard = unique_ptr<pcap_t,void(*)(pcap_t *)>(
        owns_handle ? handle : nullptr,
        [](pcap_t *h){ if(h) pcap_close(h); }
    );

    /* only for debug
        pcap_dumper_t *dumper = pcap_dump_open(handle, "/tmp/frame_ddebug.pcap");
        auto dumper_guard = unique_ptr<pcap_dumper_t, void(*)(pcap_dumper_t*)>(
            dumper,
            [](pcap_dumper_t* d) { if(d) pcap_dump_close(d); }
        );
        if (!dumper) log(LogLevel::DEBUG, "pcap_dump_open failed: %s", pcap_geterr(handle));
        */

    const string filter_str = "wlan type mgt subtype auth and wlan addr2 " + ap_mac.to_string();
    bpf_program fp{};
    if(pcap_compile(handle, &fp, filter_str.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0){
        throw runtime_error("pcap_compile failed: " + string(pcap_geterr(handle)));
    }
    pcap_setfilter(handle, &fp);
    pcap_freecode(&fp);

    const int fd = pcap_get_selectable_fd(handle);
    if(fd == -1) throw runtime_error("Pcap FD not selectable");

    const auto deadline = steady_clock::now() + seconds(timeout_sec);

    while(steady_clock::now() < deadline){
        auto now = steady_clock::now();
        const int remaining_ms = duration_cast<milliseconds>(deadline - now).count();
        if(remaining_ms <= 0) break;

        pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};
        const int ret = poll(&pfd, 1, remaining_ms);
        if(ret < 0){
            if(errno == EINTR) continue;
            break;
        }
        if(ret == 0 || !(pfd.revents & POLLIN)) continue;;
        pcap_pkthdr *header;
        const uint8_t *packet;
        while(pcap_next_ex(handle, &header, &packet) == 1){
            if(header->caplen < 10){
                log(LogLevel::DEBUG, "Packet too short: %u", header->caplen);
                continue;
            }

            log(LogLevel::DEBUG, "Hex: %02x %02x %02x %02x", packet[0], packet[1], packet[2], packet[3]);

            //if (dumper) pcap_dump(reinterpret_cast<u_char*>(dumper), header, packet);
            if(const auto frame = dos_helpers::parse_sae_commit(packet, header->caplen)){
                result = frame.value();
                log(LogLevel::DEBUG, "Captured SAE commit, scalar size: %zu", result.scalar.size());
                return result;
            }
        }
    }
    return nullopt;
}

void stop_wpa_supplicant(const string &pid_file){
    ifstream file(pid_file);
    if(file.is_open()){
        pid_t pid;
        file >> pid;
        if(pid > 0){
            log(LogLevel::INFO, "Stop wpa_supplicant (PID: " + to_string(pid) + ")");
            kill(pid, SIGTERM);
        }
        file.close();
        remove(pid_file.c_str());
    }
}

// run_cmd for logging or useless:
void start_wpa_supplicant(RunStatus &rs, const string &iface, const string &conf_path, const string &pid_file){
    if(filesystem::exists(pid_file)){ stop_wpa_supplicant(pid_file); }

    // Clean up stale socket
    const string socket = "/var/run/wpa_supplicant/" + iface;
    if(filesystem::exists(socket)) filesystem::remove(socket);

    log(LogLevel::INFO, "Run wpa_supplicant to get handshake values...");
    rs.process_manager.run("get_commit", {
                               "wpa_supplicant", "-B",
                               "-i", iface,
                               "-c", conf_path,
                               "-P", pid_file
                           });
}

string create_wpa_supplicant_config(const string &ssid){
    string conf_path = "/tmp/wpa3_guzzler_temp" + ssid + ".conf";
    ofstream conf(conf_path);

    if(conf.is_open()){
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

optional<dos_helpers::SAEPair> get_commit_values(RunStatus &rs, const string &iface, const string &sniff_iface,
                                                 const string &ssid, const HWAddress<6> &ap_mac, const int timeout,
                                                 pcap_t *handler
){
    if(iface == sniff_iface) throw invalid_argument("Interface names do cant be same");
    const string pid_file = "/tmp/wpa_supplicant_get_commit_values.pid";
    const string conf_path = create_wpa_supplicant_config(ssid);
    start_wpa_supplicant(rs, iface, filesystem::absolute(conf_path), pid_file);
    optional<dos_helpers::SAEPair> sae_params = capture_sae_commit(sniff_iface, ap_mac, timeout, handler);
    if(handler != nullptr) pcap_close(handler);
    stop_wpa_supplicant(pid_file);
    filesystem::remove(conf_path);
    return sae_params;
}
}