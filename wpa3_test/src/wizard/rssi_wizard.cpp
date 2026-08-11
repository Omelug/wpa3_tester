#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <pcap.h>
#include <radiotap.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>

#include "config/Actor_Config/Actor_Config_internal.h"
#include "system/hw_capabilities.h"

extern "C" {
#include <radiotap_iter.h>
}

static FILE* g_gnuplot_pipe = nullptr;
static volatile bool g_running = true;

void signal_handler(const int signum) {
	if (!g_running) {
		std::cerr << "\n[!] Force exiting..." << std::endl;
		std::exit(128 + signum);
	}
	g_running = false;
}

struct Node2D {
    double x{0.0};
    double y{0.0};
    double vx{0.0};
    double vy{0.0};
};

std::string normalize_mac(std::string mac) {
    std::ranges::transform(mac, mac.begin(), ::tolower);
    return mac;
}

struct WifiSender {
    std::string iface_name;
    int sock_fd{-1};

    explicit WifiSender(std::string name) : iface_name(std::move(name)) {
        sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock_fd < 0) return;

		sockaddr_ll sa{};
        std::memset(&sa, 0, sizeof(sa));
        sa.sll_family = AF_PACKET;
        sa.sll_ifindex = if_nametoindex(iface_name.c_str());
        sa.sll_protocol = htons(ETH_P_ALL);

        bind(sock_fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    }

    ~WifiSender() {
        if (sock_fd >= 0) close(sock_fd);
    }

    WifiSender(const WifiSender&) = delete;
    WifiSender& operator=(const WifiSender&) = delete;

    WifiSender(WifiSender&& other) noexcept
        : iface_name(std::move(other.iface_name)), sock_fd(other.sock_fd) {
        other.sock_fd = -1;
    }

    WifiSender& operator=(WifiSender&& other) noexcept {
        if (this != &other) {
            if (sock_fd >= 0) close(sock_fd);
            iface_name = std::move(other.iface_name);
            sock_fd = other.sock_fd;
            other.sock_fd = -1;
        }
        return *this;
    }

    bool send_frame(const uint8_t* frame, const size_t len) const{
        if (sock_fd < 0) return false;
        const ssize_t sent = send(sock_fd, frame, len, 0);
        return sent == static_cast<ssize_t>(len);
    }
};


void transmit_beacon_or_probe(const WifiSender& sender, const std::string& mac_str) {
    uint8_t mac_bytes[6]{0};
    std::sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
                &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);

    const uint8_t frame[] = {
        // Radiotap Header (8 bytes)
        0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        // IEEE 802.11 Probe Request
        0x40, 0x00,                         // Frame Control
        0x00, 0x00,                         // Duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // DA: Broadcast
        mac_bytes[0], mac_bytes[1], mac_bytes[2],
        mac_bytes[3], mac_bytes[4], mac_bytes[5], // SA
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // BSSID: Broadcast
        0x00, 0x00                          // Sequence Control
    };

    sender.send_frame(frame, sizeof(frame));
}

int8_t extract_rssi(const uint8_t* packet, const uint32_t caplen) {
	ieee80211_radiotap_iterator iter{};

	auto* header = reinterpret_cast<struct ieee80211_radiotap_header*>(
		const_cast<uint8_t*>(packet)
	);

	if (ieee80211_radiotap_iterator_init(&iter, header, static_cast<int>(caplen), nullptr) != 0) {
		return -90;
	}

	while (ieee80211_radiotap_iterator_next(&iter) == 0) {
		if (iter.is_radiotap_ns && iter.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL) {
			if (iter.this_arg != nullptr) {
				return *reinterpret_cast<const int8_t*>(iter.this_arg);
			}
		}
	}

	return -90;
}

class RssiCache {
    mutable std::mutex mutex_;
    std::map<std::pair<std::string, std::string>, double> cache_;

public:
    void update(const std::string& src_mac, const std::string& rx_iface, const double rssi) {
        std::lock_guard lock(mutex_);
        cache_[{normalize_mac(src_mac), rx_iface}] = rssi;
    }

    double get(const std::string& src_mac, const std::string& rx_iface) const {
        std::lock_guard lock(mutex_);
        const auto it = cache_.find({normalize_mac(src_mac), rx_iface});
        return it != cache_.end() ? it->second : -90.0;
    }
};

class PcapSniffer {
private:
    std::string rx_iface_;
    std::shared_ptr<RssiCache> cache_ref_;
    std::atomic<bool> running_{false};
    std::thread worker_;
	pcap_t* handle_{nullptr};

    static std::string format_mac(const uint8_t* mac) {
        char buf[18];
        std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return buf;
    }

    void sniffer_loop() {
    	char errbuf[PCAP_ERRBUF_SIZE];
    	handle_ = pcap_create(rx_iface_.c_str(), errbuf);
    	if (!handle_) return;

    	pcap_set_snaplen(handle_, 2048);
    	pcap_set_promisc(handle_, 1);
    	pcap_set_timeout(handle_, 100);
    	pcap_set_immediate_mode(handle_, 1);

    	if (pcap_activate(handle_) < 0) {
    		pcap_close(handle_);
    		handle_ = nullptr;
    		return;
    	}

    	bpf_program fp{};
    	if (pcap_compile(handle_, &fp, "type mgt subtype probe-req", 1, PCAP_NETMASK_UNKNOWN) == 0) {
    		pcap_setfilter(handle_, &fp);
    		pcap_freecode(&fp);
    	}

    	while (running_.load(std::memory_order_relaxed)) {
			pcap_pkthdr* header;
    		const uint8_t* packet;
    		const int res = pcap_next_ex(handle_, &header, &packet);

    		if (res == -2) break; // loop end
    		if (res <= 0) continue;

    		const int8_t rssi_dbm = extract_rssi(packet, header->caplen);
    		const uint16_t radiotap_len = packet[2] | (packet[3] << 8);

    		if (header->caplen >= radiotap_len + 24) {
    			const uint8_t* ieee_hdr = packet + radiotap_len;
    			const uint8_t* src_mac_bytes = ieee_hdr + 10;
    			std::string src_mac = format_mac(src_mac_bytes);

    			cache_ref_->update(src_mac, rx_iface_, rssi_dbm);
    		}
    	}

    	pcap_close(handle_);
    	handle_ = nullptr;
    }

public:
    PcapSniffer(std::string rx_iface, std::shared_ptr<RssiCache> cache)
        : rx_iface_(std::move(rx_iface)), cache_ref_(std::move(cache)) {}

    ~PcapSniffer() { stop(); }

	void start() {
    	running_ = true;
    	worker_ = std::thread(&PcapSniffer::sniffer_loop, this);
    }

	void stop() {
    	if (running_.exchange(false)) {
    		if (handle_) {
    			pcap_breakloop(handle_);
    		}
    		if (worker_.joinable()) {
    			worker_.join();
    		}
    	}
    }
};

struct NetworkSetup {
    std::vector<wpa3_tester::ActorPtr> actors;
    std::vector<WifiSender> senders;
    std::vector<std::unique_ptr<PcapSniffer>> sniffers;
    std::vector<std::string> iface_names;
    std::vector<std::string> mac_addrs;
    std::shared_ptr<RssiCache> rssi_cache{std::make_shared<RssiCache>()};
};

NetworkSetup initialize_network() {
    NetworkSetup setup;
    const auto ifaces = wpa3_tester::hw_capabilities::list_interfaces(
        wpa3_tester::InterfaceType::Wifi, std::nullopt
    );

    for (const auto& iface : ifaces) {
        try {
            auto config = std::make_shared<wpa3_tester::Actor_Config_internal>();
            config->set(wpa3_tester::SK::iface, iface.name);

            std::string mac = wpa3_tester::hw_capabilities::get_mac_address(iface.name, std::nullopt).to_string();
            config->set(wpa3_tester::SK::mac, mac);
            config->set_monitor_mode();
            config->set_iface_up();

            wpa3_tester::ActorPtr actor(config);

            setup.actors.push_back(actor);
            setup.senders.emplace_back(iface.name);
            setup.iface_names.push_back(iface.name);
            setup.mac_addrs.push_back(normalize_mac(mac));

            auto sniffer = std::make_unique<PcapSniffer>(iface.name, setup.rssi_cache);
            sniffer->start();
            setup.sniffers.push_back(std::move(sniffer));

        } catch (const std::exception& e) {
            std::cerr << "  [!] Error initializing " << iface.name << ": " << e.what() << std::endl;
        }
    }
    return setup;
}

using RssiMatrix = std::map<std::pair<std::string, std::string>, double>;

RssiMatrix collect_rssi_measurements(
    const std::vector<wpa3_tester::ActorPtr>& actors,
    const std::vector<WifiSender>& senders,
    const std::vector<std::string>& iface_names,
    const RssiCache& cache)
{
    RssiMatrix rssi_matrix;

    for (size_t i = 0; i < senders.size(); ++i) {
        std::string src_mac = actors[i]->get(wpa3_tester::SK::mac);
        transmit_beacon_or_probe(senders[i], src_mac);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    for (size_t i = 0; i < actors.size(); ++i) {
        std::string src_mac = actors[i]->get(wpa3_tester::SK::mac);

        for (size_t j = 0; j < actors.size(); ++j) {
            if (i == j) continue;

            const double rssi = cache.get(src_mac, iface_names[j]);
            rssi_matrix[{iface_names[i], iface_names[j]}] = rssi;
        }
    }

    return rssi_matrix;
}

void update_physics(
    std::map<std::string, Node2D>& nodes,
    const std::vector<std::string>& iface_names,
    const RssiMatrix& rssi_matrix)
{
    const size_t n = iface_names.size();
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            const auto& nameA = iface_names[i];
            const auto& nameB = iface_names[j];

            auto it = rssi_matrix.find({nameA, nameB});
            const double rssi = it != rssi_matrix.end() ? it->second : -90.0;

            const double target_dist = std::clamp((std::abs(rssi) - 30.0) / 7.0, 1.0, 9.0);

            auto& nodeA = nodes[nameA];
            auto& nodeB = nodes[nameB];

            const double dx = nodeB.x - nodeA.x;
            const double dy = nodeB.y - nodeA.y;
            const double dist = std::sqrt(dx * dx + dy * dy) + 0.001;

            const double force = 0.1 * (dist - target_dist);
            const double fx = dx / dist * force;
            const double fy = dy / dist * force;

            nodeA.vx += fx; nodeA.vy += fy;
            nodeB.vx -= fx; nodeB.vy -= fy;
        }
    }

    for (auto &node: nodes | std::views::values) {
        node.x += node.vx;
        node.y += node.vy;
        node.vx *= 0.5;
        node.vy *= 0.5;
    }
}

void render_gnuplot(
    FILE* pipe,
    const std::map<std::string, Node2D>& nodes,
    const std::vector<std::string>& iface_names,
    const std::vector<std::string>& mac_addrs,
    const RssiMatrix& rssi_matrix)
{
    fprintf(pipe, "plot '-' with vectors nohead lc rgb '#888888' lw 1.5 title '', "
                  "'-' with labels center tc rgb '#0066cc' font ',9' title '', "
                  "'-' with points pt 7 ps 3 lc rgb '#cc0000' title 'Adapters', "
                  "'-' with labels offset 0,1.5 center font ',9 bold' title ''\n");

    const size_t n = iface_names.size();

    // connections
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            auto itA = nodes.find(iface_names[i]);
            auto itB = nodes.find(iface_names[j]);
            if (itA != nodes.end() && itB != nodes.end()) {
                double x1 = itA->second.x, y1 = itA->second.y;
                double x2 = itB->second.x, y2 = itB->second.y;
                fprintf(pipe, "%f %f %f %f\n", x1, y1, x2 - x1, y2 - y1);
            }
        }
    }
    fprintf(pipe, "e\n");

    // 2. RSSI values
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            auto itA = nodes.find(iface_names[i]);
            auto itB = nodes.find(iface_names[j]);
            if (itA != nodes.end() && itB != nodes.end()) {
                const double mid_x = (itA->second.x + itB->second.x) / 2.0;
                const double mid_y = (itA->second.y + itB->second.y) / 2.0;

                auto rssi_it = rssi_matrix.find({iface_names[i], iface_names[j]});
                const double rssi = rssi_it != rssi_matrix.end() ? rssi_it->second : -90.0;

                fprintf(pipe, "%f %f '%.0f dBm'\n", mid_x, mid_y, rssi);
            }
        }
    }
    fprintf(pipe, "e\n");

    // points
    for (const auto& name : iface_names) {
        auto it = nodes.find(name);
        if (it != nodes.end()) {
            fprintf(pipe, "%f %f\n", it->second.x, it->second.y);
        }
    }
    fprintf(pipe, "e\n");

    // labels
    for (size_t i = 0; i < n; ++i) {
        auto it = nodes.find(iface_names[i]);
        if (it != nodes.end()) {
            fprintf(pipe, "%f %f '%s\\n%s'\n", it->second.x, it->second.y, iface_names[i].c_str(), mac_addrs[i].c_str());
        }
    }
    fprintf(pipe, "e\n");

    fflush(pipe);
}

FILE* init_gnuplot() {
    FILE* pipe = popen("gnuplot -persist", "w");
    if (!pipe) return nullptr;

    fprintf(pipe, "set title 'Wi-Fi RSSI Spring-Force Visualization'\n");
    fprintf(pipe, "set key off\n");
    fprintf(pipe, "set xrange [-10:10]\n");
    fprintf(pipe, "set yrange [-10:10]\n");
    fprintf(pipe, "set grid\n");
    fflush(pipe);
    return pipe;
}

std::map<std::string, Node2D> initialize_node_positions(const std::vector<std::string>& iface_names) {
    std::map<std::string, Node2D> nodes;
    const size_t n = iface_names.size();
    for (size_t i = 0; i < n; ++i) {
        const double angle = 2.0 * M_PI * static_cast<double>(i) / static_cast<double>(n);
        nodes[iface_names[i]] = { 5.0 * std::cos(angle), 5.0 * std::sin(angle), 0.0, 0.0 };
    }
    return nodes;
}

void run_rssi_wizard() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    const auto setup = initialize_network();
    if (setup.actors.empty()) return;

    g_gnuplot_pipe = init_gnuplot();
    if (!g_gnuplot_pipe) return;

    auto nodes = initialize_node_positions(setup.iface_names);

    while (g_running) {
        auto rssi_matrix = collect_rssi_measurements(
            setup.actors,
            setup.senders,
            setup.iface_names,
            *setup.rssi_cache
        );

        update_physics(nodes, setup.iface_names, rssi_matrix);
        render_gnuplot(g_gnuplot_pipe, nodes, setup.iface_names, setup.mac_addrs, rssi_matrix);

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    if (g_gnuplot_pipe) pclose(g_gnuplot_pipe);
}

#ifdef MAIN_TARGET_BUILD
int main() {
    run_rssi_wizard();
    return 0;
}
#endif