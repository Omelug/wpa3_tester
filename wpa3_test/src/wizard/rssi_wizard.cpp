#include <cstring>
#include <iostream>
#include <unistd.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "config/Actor_Config/Actor_Config_internal.h"
#include "system/hw_capabilities.h"

static FILE* g_gnuplot_pipe = nullptr;
static volatile bool g_running = true;

void signal_handler(int signum) {
    g_running = false;
}

struct Node2D {
    double x{0.0};
    double y{0.0};
    double vx{0.0};
    double vy{0.0};
};


// --- RAII Wrapper pro trvalý Raw Socket ---
struct WifiSender {
    std::string iface_name;
    int sock_fd{-1};

    explicit WifiSender(std::string  name) : iface_name(std::move(name)) {
        sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock_fd < 0) {
            std::cerr << "[!] Failed to create raw socket for: " << iface_name << std::endl;
            return;
        }

        struct sockaddr_ll sa{};
        std::memset(&sa, 0, sizeof(sa));
        sa.sll_family = AF_PACKET;
        sa.sll_ifindex = if_nametoindex(iface_name.c_str());
        sa.sll_protocol = htons(ETH_P_ALL);

        if (bind(sock_fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) < 0) {
            std::cerr << "[!] Socket bind failed for: " << iface_name << std::endl;
        }
    }

    ~WifiSender() {
        if (sock_fd >= 0) {
            close(sock_fd);
        }
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

    bool send_frame(const uint8_t* frame, size_t len) {
        if (sock_fd < 0) return false;
        ssize_t sent = send(sock_fd, frame, len, 0);
        return sent == static_cast<ssize_t>(len);
    }
};

using RssiMatrix = std::map<std::pair<std::string, std::string>, double>;

// --- Pomocné funkce ---

void transmit_beacon_or_probe(WifiSender& sender) {
    static const uint8_t probe_request[] = {
        0x40, 0x00,                         // Frame Control: Probe Request
        0x00, 0x00,                         // Duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // DA: Broadcast
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // SA: Sender MAC
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // BSSID: Broadcast
        0x00, 0x00,                         // Sequence Control
        0x00, 0x00                          // SSID Element
    };

    if (!sender.send_frame(probe_request, sizeof(probe_request))) {
        std::cerr << "[!] Transmit error on interface " << sender.iface_name << '\n';
    }
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
    size_t n = iface_names.size();
    for (size_t i = 0; i < n; ++i) {
        const double angle = 2.0 * M_PI * i / n;
        nodes[iface_names[i]] = { 5.0 * std::cos(angle), 5.0 * std::sin(angle), 0.0, 0.0 };
    }
    return nodes;
}

#include <atomic>
#include <mutex>
#include <pcap.h>

// Shared thread-safe RSSI storage: maps (Source MAC, Receiver Interface) -> RSSI dBm
class RssiCache {
private:
    mutable std::mutex mutex_;
    std::map<std::pair<std::string, std::string>, double> cache_;

public:
    void update(const std::string& src_mac, const std::string& rx_iface, double rssi) {
        std::lock_guard<std::mutex> lock(mutex_);
        cache_[{src_mac, rx_iface}] = rssi;
    }

    double get(const std::string& src_mac, const std::string& rx_iface) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find({src_mac, rx_iface});
        return (it != cache_.end()) ? it->second : -90.0; // Default noise floor if absent
    }
};

// Standalone sniffer managing its own background pcap thread
class PcapSniffer {
private:
    std::string rx_iface_;
    std::shared_ptr<RssiCache> cache_ref_;
    std::atomic<bool> running_{false};
    std::thread worker_;

    static std::string format_mac(const uint8_t* mac) {
        char buf[18];
        std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buf);
    }

    // Standalone loop function executing inside worker_ thread
    void sniffer_loop() {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_create(rx_iface_.c_str(), errbuf);
        if (!handle) {
            std::cerr << "[!] pcap_create failed on " << rx_iface_ << ": " << errbuf << std::endl;
            return;
        }

        pcap_set_snaplen(handle, 2048);
        pcap_set_promisc(handle, 1);
        pcap_set_timeout(handle, 10);
        pcap_set_immediate_mode(handle, 1); // Crucial: bypasses kernel buffering

        if (pcap_activate(handle) < 0) {
            std::cerr << "[!] pcap_activate failed on " << rx_iface_ << std::endl;
            pcap_close(handle);
            return;
        }

		bpf_program fp{};
    	if (pcap_compile(handle, &fp, "type mgt subtype probe-req", 1, PCAP_NETMASK_UNKNOWN) == 0) {
    		pcap_setfilter(handle, &fp);
    		pcap_freecode(&fp);
    	}


        while (running_.load(std::memory_order_relaxed)) {
            struct pcap_pkthdr* header;
            const uint8_t* packet;
            int res = pcap_next_ex(handle, &header, &packet);

            if (res <= 0) continue; // Timeout or no packet ready

            // Minimal Radiotap parsing logic
            uint16_t radiotap_len = packet[2] | (packet[3] << 8);
            if (header->caplen < radiotap_len + 24) continue; // Ensure frame header is complete

            // SSI Signal field (dBm) is typically located at offset 22 in standard Radiotap headers
            int8_t rssi_dbm = static_cast<int8_t>(packet[22]);

            // IEEE 802.11 Frame Header starts immediately after Radiotap header
            const uint8_t* ieee_hdr = packet + radiotap_len;
            const uint8_t* src_mac_bytes = ieee_hdr + 10; // Source MAC offset in 802.11 header

            std::string src_mac = format_mac(src_mac_bytes);
            cache_ref_->update(src_mac, rx_iface_, static_cast<double>(rssi_dbm));
        }

        pcap_close(handle);
    }

public:
	PcapSniffer(std::string rx_iface, std::shared_ptr<RssiCache> cache)
		: rx_iface_(std::move(rx_iface)), cache_ref_(std::move(cache)) {}

    ~PcapSniffer() {
        stop();
    }

    void start() {
        running_ = true;
        worker_ = std::thread(&PcapSniffer::sniffer_loop, this);
    }

    void stop() {
        if (running_.exchange(false) && worker_.joinable()) {
            worker_.join();
        }
    }
};

// Shared network setup wrapping state
struct NetworkSetup {
    std::vector<wpa3_tester::ActorPtr> actors;
    std::vector<WifiSender> senders;
    std::vector<std::unique_ptr<PcapSniffer>> sniffers;
    std::vector<std::string> iface_names;
	std::shared_ptr<RssiCache> rssi_cache{std::make_shared<RssiCache>()};
};

NetworkSetup initialize_network() {
	NetworkSetup setup;
	const auto ifaces = wpa3_tester::hw_capabilities::list_interfaces(
		wpa3_tester::InterfaceType::Wifi, std::nullopt
	);

	for (const auto& iface : ifaces) {
		std::cout << "  -> Found interface: " << iface.name << std::endl;
		try {
			auto config = std::make_shared<wpa3_tester::Actor_Config_internal>();
			config->set(wpa3_tester::SK::iface, iface.name);
			config->set(wpa3_tester::SK::mac, wpa3_tester::hw_capabilities::get_mac_address(iface.name, std::nullopt));
			config->set_monitor_mode();
			config->set_iface_up();

			wpa3_tester::ActorPtr actor(config);

			setup.actors.push_back(actor);
			setup.senders.emplace_back(iface.name);
			setup.iface_names.push_back(iface.name +" " + config->get(wpa3_tester::SK::mac));

			// Instantiate standalone sniffer worker per interface
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
    std::vector<WifiSender>& senders,
    const std::vector<std::string>& iface_names,
    const RssiCache& cache)
{
    RssiMatrix rssi_matrix;
    std::cout << "\n--- [Current RSSI Measurements] ---" << std::endl;

    // 1. Fire frame transmissions on all interfaces
    for (size_t i = 0; i < senders.size(); ++i) {
        transmit_beacon_or_probe(senders[i]);
    }

    // 2. Brief non-blocking wait to allow background sniffer threads to process incoming frames
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // 3. Read latest frame data directly from the thread-safe cache
    for (size_t i = 0; i < actors.size(); ++i) {
        std::string src_mac = actors[i]->get(wpa3_tester::SK::mac);

        for (size_t j = 0; j < actors.size(); ++j) {
            if (i == j) continue;

            double rssi = cache.get(src_mac, iface_names[j]);
            rssi_matrix[{iface_names[i], iface_names[j]}] = rssi;

            std::cout << iface_names[i] << " (" << src_mac << ") -> "
                      << iface_names[j] << " : " << rssi << " dBm\n";
        }
    }

    return rssi_matrix;
}

void update_physics(
	std::map<std::string, Node2D>& nodes,
	const std::vector<std::string>& iface_names,
	const RssiMatrix& rssi_matrix)
{
	size_t n = iface_names.size();
	for (size_t i = 0; i < n; ++i) {
		for (size_t j = i + 1; j < n; ++j) {
			const auto& nameA = iface_names[i];
			const auto& nameB = iface_names[j];

			auto it = rssi_matrix.find({nameA, nameB});
			double rssi = (it != rssi_matrix.end()) ? it->second : 0.0;
			if (rssi == 0.0) rssi = -90.0;

			double target_dist = std::clamp((std::abs(rssi) - 30.0) / 10.0, 1.0, 9.0);

			auto& nodeA = nodes[nameA];
			auto& nodeB = nodes[nameB];

			double dx = nodeB.x - nodeA.x;
			double dy = nodeB.y - nodeA.y;
			double dist = std::sqrt(dx * dx + dy * dy) + 0.001;

			double force = 0.1 * (dist - target_dist);
			double fx = (dx / dist) * force;
			double fy = (dy / dist) * force;

			nodeA.vx += fx; nodeA.vy += fy;
			nodeB.vx -= fx; nodeB.vy -= fy;
		}
	}

	for (auto& [name, node] : nodes) {
		node.x += node.vx;
		node.y += node.vy;
		node.vx *= 0.5;
		node.vy *= 0.5;
	}
}

void render_gnuplot(FILE* pipe, const std::map<std::string, Node2D>& nodes, const std::vector<std::string>& iface_names) {
	fprintf(pipe, "plot '-' with points pt 7 ps 3 title 'Adapters', '-' with labels offset 1,1 title ''\n");

	for (const auto& name : iface_names) {
		auto it = nodes.find(name);
		if (it != nodes.end()) {
			fprintf(pipe, "%f %f\n", it->second.x, it->second.y);
		}
	}
	fprintf(pipe, "e\n");

	for (const auto& name : iface_names) {
		auto it = nodes.find(name);
		if (it != nodes.end()) {
			fprintf(pipe, "%f %f %s\n", it->second.x, it->second.y, name.c_str());
		}
	}
	fprintf(pipe, "e\n");

	fflush(pipe);
}

void run_rssi_wizard() {
	std::signal(SIGINT, signal_handler);
	std::signal(SIGTERM, signal_handler);

	std::cout << "[RSSI Wizard] Searching for Wi-Fi interfaces..." << std::endl;
	auto setup = initialize_network();

	if (setup.actors.empty()) {
		std::cerr << "[RSSI Wizard] No valid Wi-Fi interfaces initialized in monitor mode." << std::endl;
		return;
	}

	g_gnuplot_pipe = init_gnuplot();
	if (!g_gnuplot_pipe) {
		std::cerr << "[RSSI Wizard] Failed to start Gnuplot!" << std::endl;
		return;
	}

	auto nodes = initialize_node_positions(setup.iface_names);

	std::cout << "[RSSI Wizard] Starting measurement and Gnuplot simulation. Press Ctrl+C to exit.\n";

	while (g_running) {
		// Pass setup.rssi_cache as the 4th argument
		auto rssi_matrix = collect_rssi_measurements(
			setup.actors,
			setup.senders,
			setup.iface_names,
			*setup.rssi_cache
		);

		update_physics(nodes, setup.iface_names, rssi_matrix);
		render_gnuplot(g_gnuplot_pipe, nodes, setup.iface_names);

		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

	if (g_gnuplot_pipe) {
		pclose(g_gnuplot_pipe);
		g_gnuplot_pipe = nullptr;
	}
}

#ifdef MAIN_TARGET_BUILD
int main() {
	run_rssi_wizard();
	return 0;
}
#endif