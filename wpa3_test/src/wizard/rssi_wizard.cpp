#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <linux/if_packet.h>
#include <map>
#include <memory>
#include <mutex>
#include <net/ethernet.h>
#include <net/if.h>
#include <optional>
#include <pcap.h>
#include <radiotap.h>
#include <set>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include "config/Actor_Config/Actor_Config_internal.h"
#include "config/Actor_Config/ActorPtr.h"
#include "system/hw_capabilities.h"
#include "wizard/rssi_condition.h"

extern "C" {
#include <radiotap_iter.h>
}

using namespace std;

// ---- globals ----

static FILE* g_gnuplot_pipe = nullptr;
static volatile bool g_running = true;
static atomic<bool>  g_paused{false};

void signal_handler(const int signum) {
    if (!g_running) {
        cerr << "\n[!] Force exiting...\n";
        exit(128 + signum);
    }
    g_running = false;
}

static void pause_handler(int) { g_paused = !g_paused; }

// ---- basic types ----

struct Node2D {
    double x{0.0}, y{0.0};
};

static string normalize_mac(string mac) {
    ranges::transform(mac, mac.begin(), ::tolower);
    return mac;
}

// ---- WifiSender ----

struct WifiSender {
    string iface_name;
    int sock_fd{-1};

    explicit WifiSender(string name) : iface_name(move(name)) {
        sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock_fd < 0) return;

        sockaddr_ll sa{};
        sa.sll_family   = AF_PACKET;
        sa.sll_ifindex  = static_cast<int>(if_nametoindex(iface_name.c_str()));
        sa.sll_protocol = htons(ETH_P_ALL);

        if (bind(sock_fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
            close(sock_fd);
            sock_fd = -1;
        }
    }

    ~WifiSender() { if (sock_fd >= 0) close(sock_fd); }

    WifiSender(const WifiSender&)            = delete;
    WifiSender& operator=(const WifiSender&) = delete;

    WifiSender(WifiSender&& o) noexcept
        : iface_name(move(o.iface_name)), sock_fd(o.sock_fd) { o.sock_fd = -1; }

    WifiSender& operator=(WifiSender&& o) noexcept {
        if (this != &o) {
            if (sock_fd >= 0) close(sock_fd);
            iface_name = move(o.iface_name);
            sock_fd    = o.sock_fd;
            o.sock_fd  = -1;
        }
        return *this;
    }

    bool send_frame(const uint8_t* frame, size_t len) const {
        if (sock_fd < 0) return false;
        return send(sock_fd, frame, len, 0) == static_cast<ssize_t>(len);
    }
};

static void transmit_probe(const WifiSender& sender, const string& mac_str) {
    uint8_t mac[6]{};
    const char* p = mac_str.c_str();
    for (int i = 0; i < 6; ++i) {
        char* end;
        mac[i] = static_cast<uint8_t>(strtoul(p, &end, 16));
        p = end + 1;
    }

    const uint8_t frame[] = {
        0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,  // Radiotap header (8 bytes)
        0x40, 0x00,                                        // Frame control: Probe Request
        0x00, 0x00,                                        // Duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,               // DA: broadcast
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],   // SA
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,               // BSSID: broadcast
        0x00, 0x00,                                        // Sequence control
        0x00, 0x00,                                        // SSID IE: tag=0, len=0 (wildcard)
    };
    sender.send_frame(frame, sizeof(frame));
}

// ---- RSSI extraction ----

constexpr int8_t DEFAULT_RSSI = -90;

static int8_t extract_rssi(const uint8_t* packet, const uint32_t caplen) {
    ieee80211_radiotap_iterator iter{};
    auto* hdr = reinterpret_cast<ieee80211_radiotap_header*>(const_cast<uint8_t*>(packet));
    if (ieee80211_radiotap_iterator_init(&iter, hdr, static_cast<int>(caplen), nullptr) != 0)
        return DEFAULT_RSSI;
    while (ieee80211_radiotap_iterator_next(&iter) == 0) {
        if (iter.is_radiotap_ns
            && iter.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL
            && iter.this_arg)
            return *reinterpret_cast<const int8_t*>(iter.this_arg);
    }
    return DEFAULT_RSSI;
}

// ---- RSSI cache ----

class RssiCache {
    mutable mutex mtx_;
    map<pair<string,string>, double> data_;  // {src_mac, rx_iface} → dBm
public:
    void update(const string& src_mac, const string& rx_iface, double rssi) {
        lock_guard lock(mtx_);
        data_[{normalize_mac(src_mac), rx_iface}] = rssi;
    }
    double get(const string& src_mac, const string& rx_iface) const {
        lock_guard lock(mtx_);
		const auto it = data_.find({normalize_mac(src_mac), rx_iface});
        return it != data_.end() ? it->second : DEFAULT_RSSI;
    }
};

// ---- PcapSniffer ----

class PcapSniffer {
    string rx_iface_;
    shared_ptr<RssiCache> cache_;
    atomic<bool> running_{false};
    thread worker_;
    pcap_t* handle_{nullptr};

    static string format_mac(const uint8_t* m) {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                 m[0], m[1], m[2], m[3], m[4], m[5]);
        return buf;
    }

    void loop() {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle_ = pcap_create(rx_iface_.c_str(), errbuf);
        if (!handle_) return;
        pcap_set_snaplen(handle_, 2048);
        pcap_set_promisc(handle_, 1);
        pcap_set_timeout(handle_, 100);
        pcap_set_immediate_mode(handle_, 1);
        if (pcap_activate(handle_) < 0) { pcap_close(handle_); handle_ = nullptr; return; }

        bpf_program fp{};
        if (pcap_compile(handle_, &fp, "type mgt subtype probe-req", 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(handle_, &fp);
            pcap_freecode(&fp);
        }

        while (running_.load(memory_order_relaxed)) {
            pcap_pkthdr* hdr; const uint8_t* pkt;
            const int res = pcap_next_ex(handle_, &hdr, &pkt);
            if (res == -2) break;
        	if (res <= 0) {
        		this_thread::sleep_for(chrono::milliseconds(10));
        		continue;
        	}
            const int8_t rssi = extract_rssi(pkt, hdr->caplen);
            const auto rlen = static_cast<uint16_t>(pkt[2] | (pkt[3] << 8));
            if (hdr->caplen >= static_cast<uint32_t>(rlen) + 24 && rssi != DEFAULT_RSSI)
                cache_->update(format_mac(pkt + rlen + 10), rx_iface_, rssi);
        }
        pcap_close(handle_); handle_ = nullptr;
    }

public:
    PcapSniffer(string iface, shared_ptr<RssiCache> c)
        : rx_iface_(move(iface)), cache_(move(c)) {}
    ~PcapSniffer() { stop(); }

    void start() { running_ = true; worker_ = thread(&PcapSniffer::loop, this); }
    void stop() {
        if (running_.exchange(false)) {
            if (handle_) pcap_breakloop(handle_);
            if (worker_.joinable()) worker_.join();
        }
    }
};

// ---- Dynamic network setup ----

struct AdapterInfo {
    wpa3_tester::ActorPtr actor;
    WifiSender sender;
    unique_ptr<PcapSniffer> sniffer;
};

struct NetworkSetup {
    mutex mtx;
    vector<AdapterInfo> adapters;
    map<string, Node2D> nodes;  // keyed by normalized MAC (persists across reconnects)
    shared_ptr<RssiCache> rssi_cache{make_shared<RssiCache>()};
};

// Caller must hold setup.mtx (or call before threads start).
static void add_adapter(NetworkSetup& setup, const string& iface_name) {
    try {
        const auto cfg = make_shared<wpa3_tester::Actor_Config_internal>();
        cfg->set(wpa3_tester::SK::iface, iface_name);
        cfg->set(wpa3_tester::SK::mac,
            wpa3_tester::hw_capabilities::get_mac_address(iface_name, nullopt));
        cfg->set_monitor_mode();
        cfg->set_iface_up();
        cfg->set_channel({6}); //FIXME hardcoded

        wpa3_tester::ActorPtr actor{cfg};
        const string mac = actor.get(wpa3_tester::SK::mac);

        if (!setup.nodes.contains(mac)) {
            const size_t idx = setup.adapters.size();
            const double angle = 2.0 * M_PI * static_cast<double>(idx)
                                 / static_cast<double>(max(idx + 1, size_t{1}));
            setup.nodes[mac] = {5.0 * cos(angle), 5.0 * sin(angle)};
        }

        WifiSender sender(iface_name);
        auto sniffer = make_unique<PcapSniffer>(iface_name, setup.rssi_cache);
        sniffer->start();
        setup.adapters.push_back({move(actor), move(sender), move(sniffer)});
    } catch (const exception& e) {
        cerr << "[!] Failed to add adapter " << iface_name << ": " << e.what() << "\n";
    }
}

static unique_ptr<NetworkSetup> initialize_network() {
    auto setup = make_unique<NetworkSetup>();
    for (const auto& iface : wpa3_tester::hw_capabilities::list_interfaces(
            wpa3_tester::InterfaceType::Wifi, nullopt))
        add_adapter(*setup, iface.name);
    return setup;
}

// Background thread: detects plug/unplug every 3 s.
static thread start_watcher(NetworkSetup& setup) {
    return thread([&setup]() {
        while (g_running) {
            this_thread::sleep_for(chrono::seconds(3));

            const auto ifaces = wpa3_tester::hw_capabilities::list_interfaces(
                wpa3_tester::InterfaceType::Wifi, nullopt);
            set<string> live;
            for (const auto& i : ifaces) live.insert(i.name);

            lock_guard lock(setup.mtx);

            for (auto it = setup.adapters.begin(); it != setup.adapters.end(); ) {
                const string iface = it->actor.get(wpa3_tester::SK::iface);
                if (!live.contains(iface)) {
                    cerr << "[*] Adapter removed: " << iface << "\n";
                    it->sniffer->stop();
                    setup.nodes.erase(it->actor.get(wpa3_tester::SK::mac));
                    it = setup.adapters.erase(it);
                } else {
                    ++it;
                }
            }

            set<string> present;
            for (const auto& a : setup.adapters) present.insert(a.actor.get(wpa3_tester::SK::iface));
            for (const auto& iface : ifaces) {
                if (!present.contains(iface.name)) {
                    cerr << "[*] Adapter added: " << iface.name << "\n";
                    add_adapter(setup, iface.name);
                }
            }
        }
    });
}

// ---- Measurement ----

// Caller must hold setup.mtx.
static RssiMatrix collect_rssi(const NetworkSetup& setup) {
    for (const auto& a : setup.adapters)
        transmit_probe(a.sender, a.actor.get(wpa3_tester::SK::mac));

    RssiMatrix m;
    for (const auto& src : setup.adapters)
        for (const auto& rx : setup.adapters) {
            const string src_mac = src.actor.get(wpa3_tester::SK::mac);
            const string rx_mac  = rx.actor.get(wpa3_tester::SK::mac);
            if (src_mac != rx_mac)
                m[{src_mac, rx_mac}] = setup.rssi_cache->get(
                    src_mac, rx.actor.get(wpa3_tester::SK::iface));
        }
    return m;
}

// ---- SMACOF layout ----

static double rssi_to_target(double rssi) {
	if (rssi <= DEFAULT_RSSI) return 10.0;  // Bez měření -> daleko

	// Pokud ovladač poslal kladné číslo (SNR / RSSI bez znaménka), převedeme na záporné
	if (rssi > 0) rssi = -rssi;

	// Přepočet RSSI (-20 dBm až -90 dBm) na vzdálenost na plátně (1.0 až 9.0 jednotek)
	// -20 dBm -> vzdálenost ~1.0 (velmi blízko)
	// -90 dBm -> vzdálenost ~8.0 (daleko)
	double dist = (abs(rssi) - 20.0) / 10.0;

	return std::clamp(dist, 0.5, 9.0);
}

// One Guttman (SMACOF) iteration — monotonically minimises layout stress.
static void smacof_step(map<string, Node2D>& nodes,
                        const vector<string>& macs,
                        const RssiMatrix& m) {
    const size_t n = macs.size();
    vector<pair<double, double>> next(n);
    for (size_t i = 0; i < n; ++i) {
        double sx = 0, sy = 0;
        const Node2D& ni = nodes[macs[i]];
        for (size_t j = 0; j < n; ++j) {
            if (i == j) continue;
            const Node2D& nj = nodes[macs[j]];
            const double dx = ni.x - nj.x, dy = ni.y - nj.y;
            const double dist = sqrt(dx*dx + dy*dy) + 1e-6;
            double rssi_sum = 0; int rssi_n = 0;
            for (const auto& key : {make_pair(macs[i], macs[j]), make_pair(macs[j], macs[i])}) {
                auto it = m.find(key);
                if (it != m.end() && it->second > DEFAULT_RSSI) { rssi_sum += it->second; ++rssi_n; }
            }
            const double rssi = rssi_n > 0 ? rssi_sum / rssi_n : DEFAULT_RSSI;
            const double d = rssi_to_target(rssi);
            sx += nj.x + d * dx / dist;
            sy += nj.y + d * dy / dist;
        }
        next[i] = {sx / static_cast<double>(n - 1), sy / static_cast<double>(n - 1)};
    }
    for (size_t i = 0; i < n; ++i) {
        nodes[macs[i]].x = next[i].first;
        nodes[macs[i]].y = next[i].second;
    }
}

static void update_positions(map<string, Node2D>& nodes,
                             const vector<AdapterInfo>& adapters,
                             const RssiMatrix& m) {
    if (adapters.size() < 2) return;
    vector<string> macs(adapters.size());
    for (size_t i = 0; i < adapters.size(); ++i)
        macs[i] = adapters[i].actor.get(wpa3_tester::SK::mac);
    for (int i = 0; i < 5; ++i)   // 5 iterations/tick — fast convergence for small N
        smacof_step(nodes, macs, m);
}

// ---- Rendering ----

static bool render(FILE* pipe,
                   const map<string, Node2D>& nodes,
                   const vector<AdapterInfo>& adapters,
                   const RssiMatrix& m,
                   const string& status) {
    fprintf(pipe, "set title 'Wi-Fi RSSI Wizard — %s'\n", status.c_str());
    fprintf(pipe,
        "plot '-' with vectors arrowstyle 1 title '', "
             "'-' with labels center tc rgb '#0066cc' font ',8' title '', "
             "'-' with points pt 7 ps 3 lc rgb '#cc0000' title 'Adapters', "
             "'-' with labels offset 0,1.5 center font ',9 bold' title ''\n");

    // Each ordered pair (i,j) draws one directional arrow, offset perpendicularly.
    // Because the perpendicular flips with direction, i→j and j→i land on opposite sides.
    constexpr double OFFSET = 0.15;
    const size_t n = adapters.size();

    auto for_pairs = [&](auto fn) {
        for (size_t i = 0; i < n; ++i)
            for (size_t j = 0; j < n; ++j) {
                if (i == j) continue;
                auto ni = nodes.find(adapters[i].actor.get(wpa3_tester::SK::mac));
                auto nj = nodes.find(adapters[j].actor.get(wpa3_tester::SK::mac));
                if (ni == nodes.end() || nj == nodes.end()) continue;
                const double dx   = nj->second.x - ni->second.x;
                const double dy   = nj->second.y - ni->second.y;
                const double dist = sqrt(dx*dx + dy*dy) + 0.001;
                const double px   = -dy/dist * OFFSET;
                const double py   =  dx/dist * OFFSET;
                fn(i, j, ni->second, nj->second, dx, dy, px, py);
            }
    };

    // Dataset 1: arrows
    for_pairs([&](size_t, size_t, const Node2D& ni, const Node2D&, double dx, double dy, double px, double py) {
        fprintf(pipe, "%f %f %f %f\n", ni.x + px, ni.y + py, dx, dy);
    });
    fprintf(pipe, "e\n");

    // Dataset 2: RSSI labels at midpoint of each directed arrow
    for_pairs([&](size_t i, size_t j, const Node2D& ni, const Node2D& nj, double, double, double px, double py) {
        const double mx = (ni.x + nj.x) / 2.0 + px;
        const double my = (ni.y + nj.y) / 2.0 + py;
        const auto it = m.find({adapters[i].actor.get(wpa3_tester::SK::mac),
                                 adapters[j].actor.get(wpa3_tester::SK::mac)});
        const double rssi = it != m.end() ? it->second : static_cast<double>(DEFAULT_RSSI);
        fprintf(pipe, "%f %f '%.0f'\n", mx, my, rssi);
    });
    fprintf(pipe, "e\n");

    // Dataset 3: node points
    for (const auto& a : adapters) {
        auto it = nodes.find(a.actor.get(wpa3_tester::SK::mac));
        if (it != nodes.end())
            fprintf(pipe, "%f %f\n", it->second.x, it->second.y);
    }
    fprintf(pipe, "e\n");

    // Dataset 4: node labels (iface + MAC)
    for (const auto& a : adapters) {
        const string mac   = a.actor.get(wpa3_tester::SK::mac);
        const string iface = a.actor.get(wpa3_tester::SK::iface);
        auto it = nodes.find(mac);
        if (it != nodes.end())
            fprintf(pipe, "%f %f '%s\\n%s'\n",
                    it->second.x, it->second.y, iface.c_str(), mac.c_str());
    }
    fprintf(pipe, "e\n");
    return fflush(pipe) == 0;
}

// ---- Gnuplot init ----

static FILE* init_gnuplot() {
    FILE* p = popen("gnuplot", "w");  // no -persist: window closes when pipe closes
    if (!p) return nullptr;
    fprintf(p, "set key off\n");
    fprintf(p, "set xrange [-10:10]\n");
    fprintf(p, "set yrange [-10:10]\n");
    fprintf(p, "set grid\n");
    fprintf(p, "set style arrow 1 head filled size graph 0.02,15 lc rgb '#888888' lw 1.5\n");
    // Key bindings: route Ctrl+C and P back to our process via signals
    const int pid = getpid();
    fprintf(p, "bind \"ctrl-c\" \"system('kill -INT %d'); exit\"\n", pid);
    fprintf(p, "bind \"p\" \"system('kill -USR1 %d')\"\n", pid);
    fflush(p);
    return p;
}

// ---- Main wizard ----

void run_rssi_wizard(const string& condition_str = "") {
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGUSR1, pause_handler);

    ExprPtr cond;
    try { cond = parse_condition(condition_str); }
    catch (const exception& e) { cerr << "[!] Condition parse error: " << e.what() << "\n"; return; }

	const auto setup = initialize_network();
    if (setup->adapters.empty()) { cerr << "[!] No Wi-Fi adapters found\n"; return; }

    g_gnuplot_pipe = init_gnuplot();
    if (!g_gnuplot_pipe) { cerr << "[!] Failed to open gnuplot\n"; return; }

    auto watcher = start_watcher(*setup);

    while (g_running) {
        {
            lock_guard lock(setup->mtx);
            if (!setup->adapters.empty()) {
                auto m = collect_rssi(*setup);
                update_positions(setup->nodes, setup->adapters, m);
                const string status = cond
                    ? (cond->eval(m) ? "CONDITION MET" : "CONDITION NOT MET")
                    : (g_paused ? "PAUSED — P to resume" : "running");
                if (!g_paused) {
                    if (!render(g_gnuplot_pipe, setup->nodes, setup->adapters, m, status))
                        g_running = false;
                }
            }
        }
        this_thread::sleep_for(chrono::milliseconds(1000));
    }

    watcher.join();
    if (g_gnuplot_pipe) { pclose(g_gnuplot_pipe); g_gnuplot_pipe = nullptr; }
    cerr << "\n[*] Stopped. Press Enter to exit...\n";
    cin.get();
}

#ifdef MAIN_TARGET_BUILD
int main() {
    // Condition: link A↔B must be stronger than -70 dBm
    //        AND stronger than link C↔B,
    //        AND NOT weaker than -90 dBm on the A↔B link
    const string condition =
        "(00:c0:ca:b5:e1:58 <-> 90:de:80:6c:90:92) > -70 && "
        "(00:c0:ca:b5:e1:58 <-> 90:de:80:6c:90:92) > (00:c0:ca:b7:69:2a <-> 90:de:80:6c:90:92) && "
        "!(00:c0:ca:b5:e1:58 <-> 90:de:80:6c:90:92) < -90";
    run_rssi_wizard(condition);
    return 0;
}
#endif
