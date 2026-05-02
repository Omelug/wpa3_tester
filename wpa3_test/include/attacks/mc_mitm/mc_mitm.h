#pragma once
#include <string>
#include <queue>
#include <memory>
#include <tins/tins.h>
#include "client_state.h"
#include "MonitorSocket.h"
#include "logger/log.h"

namespace wpa3_tester{
class McMitm{
protected:
    ActorPtr rogue_sta, rogue_ap;
    std::string nic_real_ap, nic_rogue_ap;
    std::string ssid;
    Tins::HWAddress<6> ap_mac;
    bool only_to_mitm = false;
    bool stop_mitm = false;
public:
    // AP <-> rogue_sta <-> rogue AP <-> client
    McMitm(const ActorPtr &rogue_sta, const ActorPtr &rogue_ap, std::string ssid, const std::string &ap_mac,
           const std::string &client_mac, bool only_to_mitm = false
    );
    virtual ~McMitm();

    void send_csa_beacon(int numpairs = 1, const std::optional<Tins::HWAddress<6>> &target = std::nullopt) const;
    void send_disas(const Tins::HWAddress<6> &macaddr) const;
    void send_deauth_as_ap() const;
    bool should_check_rogue_beacons() const;
    void configure_interfaces();

    void setup_real_AP_RSN_frames();
    void run(RunStatus &rs, int timeout_sec);
    void stop();

    //static void setup_ifaces(const ActorPtr &att_real, const std::string &client_mac, const ActorPtr &att_rogue, const std::string &ap_mac);

    // ---- state ----
    NetworkConfig netconfig;

    std::unique_ptr<Tins::Dot11Beacon> beacon;
    std::unique_ptr<Tins::Dot11ProbeResponse> probe_resp;
    using DisasEntry = std::pair<std::chrono::steady_clock::time_point,Tins::HWAddress<6>>;
    std::vector<DisasEntry> disas_queue;

    // move to private and add exists_client ?
    ClientState client_state;

    std::unique_ptr<MonitorSocket> sock_real;
    std::unique_ptr<MonitorSocket> sock_rogue;

    using time_point = std::chrono::steady_clock::time_point;
    time_point last_real_beacon;
    time_point last_rogue_beacon;
    time_point last_print_real_chan;
    time_point last_print_rogue_chan;

    static void patch_channel_raw(std::vector<uint8_t> &beacon_raw, uint8_t channel);

    //TODO protected + fixture
public: // for handle function is return -> end pdu processing
    //bool handle_beacon_rogue(Tins::HWAddress<6> addr2, const Tins::Dot11 & dot11);
    bool handle_probe(Tins::HWAddress<6> addr2, const Tins::PDU * pdu, const Tins::Dot11 & dot11);
    bool handle_open_auth(const Tins::HWAddress<6> &addr2, Tins::Dot11 &dot11);
    bool handle_assoc_request(const Tins::HWAddress<6> &addr2, Tins::Dot11 &dot11);
    bool handle_action_rogue(Tins::HWAddress<6> addr2, Tins::PDU &pdu, const Tins::Dot11 &dot11) const;
    bool handle_eapol_rogue(Tins::HWAddress<6> addr2, Tins::PDU &pdu);

    bool handle_probe_real(Tins::HWAddress<6> addr2, const Tins::Dot11 &dot11) const;
    bool handle_auth_from_client_real(Tins::HWAddress<6> addr1, const Tins::Dot11 &dot11);
    bool handle_action_real(const Tins::HWAddress<6> &addr2, Tins::PDU &pdu,
        const std::vector<unsigned char> &raw,  const Tins::Dot11 &dot11) const;
    bool handle_eapol_real(Tins::HWAddress<6> addr2, Tins::PDU &pdu) const;
    void handle_from_ap_real(const std::unique_ptr<Tins::PDU> &pdu, const Tins::Dot11 &dot11,
        const Tins::HWAddress<6> &addr1);

protected:
    void power_mgmt_response(Tins::HWAddress<6> addr2, const Tins::Dot11 &dot11) const;
    virtual void send_to_real(Tins::PDU &pdu) const;
    virtual void send_to_real(const std::vector<uint8_t> &raw) const;
    //virtual void send_to_real(const std::vector<uint8_t> &raw) const;
    virtual void send_to_rogue(Tins::PDU &pdu) const;
    virtual void send_to_rogue(const std::vector<uint8_t> &raw) const;
public:
    void handle_rx_real_chan(const std::unique_ptr<Tins::PDU> &pdu, const std::vector<unsigned char> &raw);
    void handle_rx_rogue_chan(const std::unique_ptr<Tins::PDU> &pdu, const std::vector<unsigned char> &raw);

    // print helpers
    static std::string frame_to_str(const Tins::Dot11 &pkt);
private:
    static void print_rx(LogLevel level, const std::string &prefix,
                         const Tins::Dot11 &frame,
                         const std::string &suffix = ""
    );
public:
    static void display_traffic(
        const Tins::PDU &pdu,
        const std::string &prefix,
        const std::string &suffix = ""
    );
};
}