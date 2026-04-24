#pragma once
#include <string>
#include <unordered_map>
#include <queue>
#include <memory>
#include <tins/tins.h>
#include "client_state.h"
#include "MonitorSocket.h"
#include "logger/log.h"

namespace wpa3_tester{
class McMitm{
private:
    ActorPtr rogue_sta, rogue_ap;
    //std::string nic_real_mon,nic_rogue_mon
    std::string nic_real_ap, nic_rogue_ap;
    std::string ssid;
    Tins::HWAddress<6> ap_mac;
    Tins::HWAddress<6> client_mac;
public:
    // AP <-> rogue_sta <-> rogue AP <-> client
    McMitm(const ActorPtr &rogue_sta, const ActorPtr &rogue_ap, std::string ssid, const std::string &ap_mac,
           const std::string &client_mac
    );
    ~McMitm();

    void send_csa_beacon(int numpairs = 1, const std::optional<Tins::HWAddress<6>> &target = std::nullopt) const;
    void send_disas(const Tins::HWAddress<6> &macaddr) const;
    void queue_disas(const Tins::HWAddress<6> &macaddr);
    void try_channel_switch(const Tins::HWAddress<6> &macaddr);
    void send_deauth_as_ap() const;
    bool should_check_rogue_beacons() const;
    void configure_interfaces();

    void run(RunStatus &rs, int timeout_sec);
    void stop();

    //static void setup_ifaces(const ActorPtr &att_real, const std::string &client_mac, const ActorPtr &att_rogue, const std::string &ap_mac);

    // ---- state ----
    NetworkConfig netconfig;

    std::unique_ptr<Tins::Dot11Beacon> beacon_old;
    std::unique_ptr<Tins::Dot11Beacon> beacon;
    std::unique_ptr<Tins::Dot11ProbeResponse> probe_resp;
    using DisasEntry = std::pair<std::chrono::steady_clock::time_point,Tins::HWAddress<6>>;
    std::vector<DisasEntry> disas_queue;

    std::unordered_map<std::string,std::unique_ptr<ClientState>> clients;

    std::unique_ptr<MonitorSocket> sock_real;
    std::unique_ptr<MonitorSocket> sock_rogue;

    using time_point = std::chrono::steady_clock::time_point;
    time_point last_real_beacon;
    time_point last_rogue_beacon;
    time_point last_print_real_chan;
    time_point last_print_rogue_chan;

    static void patch_channel_raw(std::vector<uint8_t> &beacon_raw, uint8_t channel);
    void handle_rx_real_chan();
    void handle_rx_rogue_chan();

    ClientState *find_client(const std::string &mac);

    void add_client(ClientState client){
        clients[client.macaddr] = std::make_unique<ClientState>(std::move(client));
    }

    void del_client(const Tins::HWAddress<6> &macaddr){ clients.erase(macaddr.to_string()); }

    // print helpers
    static std::string frame_to_str(const Tins::Dot11 &pkt);
    static void print_rx(LogLevel level, const std::string &prefix,
                         const Tins::Dot11 &frame,
                         const std::string &suffix = ""
    );

    static time_point display_client_traffic(
        const Tins::PDU &pdu,
        const std::string &prefix,
        time_point prevtime, const std::string &suffix = ""
    );
};
}