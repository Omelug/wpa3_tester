#pragma once
#include <string>
#include <unordered_map>
#include <queue>
#include <memory>
#include <tins/tins.h>
#include "client_state.h"
#include "logger/log.h"

namespace wpa3_tester{
    class McMitm {
    public:
        McMitm(const std::string& nic_real,
               const std::string& nic_rogue,
               const std::string& nic_real_mon,
               const std::string& nic_rogue_mon,
               const std::string& ssid,
               const std::string& client_mac);

        ~McMitm();

        void run(int timeout_sec);
        void stop();
        static void setup_ifaces(const ActorPtr &att_real, const std::string &client_mac, const ActorPtr &att_rogue, const std::string &ap_mac);

        std::string nic_real_ap, nic_rogue_ap, nic_real_mon, nic_rogue_mon;
        std::string ssid;
        std::string client_mac;

        // ---- state ----
        std::string ap_mac;
        NetworkConfig netconfig;
        std::unique_ptr<Tins::Dot11Beacon>       beacon;
        std::unique_ptr<Tins::Dot11ProbeResponse> probe_resp;

        std::unordered_map<std::string, std::unique_ptr<ClientState>> clients;

        // (scheduled_time, macaddr) — min-heap
        using DisasEntry = std::pair<double, std::string>;
        std::priority_queue<DisasEntry,
                            std::vector<DisasEntry>,
                            std::greater<DisasEntry>> disas_queue;

        std::unique_ptr<Tins::PacketSender> sender_real;
        std::unique_ptr<Tins::PacketSender> sender_rogue;

        std::unique_ptr<Tins::Sniffer> sniffer_real;
        std::unique_ptr<Tins::Sniffer> sniffer_rogue;

        double last_real_beacon  = 0.0;
        double last_rogue_beacon = 0.0;
        double last_print_real_chan  = 0.0;
        double last_print_rogue_chan = 0.0;

        static double now_sec();
        void send_disas(const std::string &macaddr) const;
        void handle_rx_real_chan(Tins::PDU& pdu);
        void handle_rx_rogue_chan(Tins::PDU& pdu);

        void add_client(std::unique_ptr<ClientState> client);
        void del_client(const std::string& macaddr);
        ClientState* find_client(const std::string& mac);

        // print helpers
        static std::string frame_to_str(const Tins::Dot11 &pkt);
        static void print_rx(LogLevel level, const std::string &prefix,
                             const Tins::Dot11 &pkt,
                             const std::string &suffix = "");

        static double display_client_traffic(const Tins::Dot11& pkt,
                                             const std::string& prefix,
                                             double prevtime,
                                             const std::string& suffix = "");
    };
}