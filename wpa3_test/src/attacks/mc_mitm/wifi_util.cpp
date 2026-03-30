#include "attacks/mc_mitm/wifi_util.h"

#include <cstdio>
#include <fstream>
#include <regex>
#include <array>
#include <stdexcept>

#include <tins/tins.h>

#include "logger/log.h"
#include "system/hw_capabilities.h"

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------
using namespace std;
void exec(const vector<string>& cmd, bool check) {
    string full;
    for (auto& s : cmd) full += s + " ";
    int ret = system(full.c_str());
    if (check && ret != 0)
        throw runtime_error("Command failed: " + full);
}

/*string exec_output(const vector<string>& cmd) {
    string full;
    for (auto& s : cmd) full += s + " ";
    array<char, 256> buf;
    string result;
    FILE* pipe = popen(full.c_str(), "r");
    if (!pipe) throw runtime_error("popen failed: " + full);
    while (fgets(buf.data(), buf.size(), pipe))
        result += buf.data();
    pclose(pipe);
    return result;
}*/

// ---------------------------------------------------------------------------
// Interface helpers
// ---------------------------------------------------------------------------

string get_macaddress(const string& iface) {
    ifstream f("/sys/class/net/" + iface + "/address");
    string mac;
    getline(f, mac);
    return mac;
}

void set_macaddress(const string& iface, const string& mac) {
    if (get_macaddress(iface) == mac) return;
    exec({"ifconfig", iface, "down"});
    exec({"macchanger", "-m", mac, iface});
}

/*int get_channel(const string& iface) {
    string out = exec_output({"iw", iface, "info"});
    regex re("channel (\\d+)");
    smatch m;
    if (!regex_search(out, m, re)) return -1;
    return stoi(m[1]);
}*/

void set_channel(const string& iface, int channel) {
    exec({"iw", iface, "set", "channel", to_string(channel)});
}

int chan2freq(int channel) {
    if (channel >= 1 && channel <= 13)
        return 2412 + (channel - 1) * 5;
    if (channel == 14)
        return 2484;
    throw runtime_error("Unsupported channel: " + to_string(channel));
}

string get_iface_type(const string& iface) {
    const string out = wpa3_tester::hw_capabilities::run_cmd_output({"iw", iface, "info"});
    const regex re("type (\\w+)");
    smatch m;
    if (!regex_search(out, m, re)) return "";
    return m[1];
}

string get_device_driver(const string& iface) {
    try {
        string out =  wpa3_tester::hw_capabilities::run_cmd_output(
            {"readlink", "-f", "/sys/class/net/" + iface + "/device/driver"});
        if (out.empty()) return "";
        // strip trailing newline then get last path component
        while (!out.empty() && (out.back() == '\n' || out.back() == '\r'))
            out.pop_back();
        const auto pos = out.rfind('/');
        return (pos == string::npos) ? out : out.substr(pos + 1);
    } catch (...) {
        return "";
    }
}

void set_monitor_mode(const string& iface, bool up, int mtu) {
    if (get_iface_type(iface) != "monitor") {
        exec({"ifconfig", iface, "down"});
        exec({"iw", iface, "set", "type", "monitor"});
        // Some kernels need the command twice
        exec({"iw", iface, "set", "type", "monitor"}, false);
    }
    if (up)
        exec({"ifconfig", iface, "up"});
    exec({"ifconfig", iface, "mtu", to_string(mtu)});
}

bool set_monitor_active(const string& iface) {
    exec({"ifconfig", iface, "down"});
    try {
        exec({"iw", iface, "set", "monitor", "active"});
        return true;
    } catch (...) {
        log(wpa3_tester::LogLevel::WARNING, "Interface " + iface + " doesn't support active monitor mode");
        return false;
    }
}

void set_ap_mode(const string& iface) {
    exec({"ifconfig", iface, "down"});
    if (get_iface_type(iface) != "AP")
        exec({"iw", iface, "set", "type", "__ap"});
    exec({"ifconfig", iface, "up"});
}

void start_ap(const string& iface, const int channel, Tins::Dot11Beacon* beacon) {
    string ssid = "";
    string head_hex, tail_hex;

    if (beacon) {
        const Tins::PDU::serialization_type raw = beacon->serialize();
        // For simplicity we pass the whole beacon as head (no tail split here)
        // A more complete impl would split at TIM; left as a TODO
        head_hex.reserve(raw.size() * 2);
        for (const uint8_t b : raw) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", b);
            head_hex += buf;
        }
        if (ssid.empty())
            ssid = get_ssid(*beacon);
    }

    if (ssid.empty())
        ssid = "libwifi-ap-" + get_macaddress(iface);

    vector<string> cmd = {
        "iw", "dev", iface, "ap", "start",
        ssid, to_string(chan2freq(channel)),
        "100", "1"  // beacon interval TU, DTIM period
    };
    if (!head_hex.empty())
        cmd.insert(cmd.end(), {"head", head_hex});

    set_ap_mode(iface);
    log(wpa3_tester::LogLevel::INFO, "Starting AP: " + [&]{ string s; for (auto& t:cmd) s+=t+" "; return s; }());
    exec(cmd);
    exec({"ifconfig", iface, "up"});
}

void stop_ap(const string& iface) {
    log(wpa3_tester::LogLevel::INFO, "Stopping AP on " + iface);
    exec({"iw", "dev", iface, "ap", "stop"});
}

// ---------------------------------------------------------------------------
// 802.11 frame helpers
// ---------------------------------------------------------------------------

bool dot11_is_encrypted_data(const Tins::Dot11Data& pkt) {
    return pkt.wep();
}

bool dot11_is_group(const Tins::Dot11& pkt) {
    // Group-addressed = LSB of first byte of addr1 is set
    const auto& a = pkt.addr1();
    return (a[0] & 0x01) != 0;
}

string get_ssid(const Tins::Dot11Beacon& beacon) {
    auto opt = beacon.search_option(Tins::Dot11::SSID);
    if (!opt) return "";
    return string(opt->data_ptr(), opt->data_ptr() + opt->data_size());
}

const Tins::Dot11::option* get_element(const Tins::Dot11& pkt, uint8_t id) {
    for (const auto& opt : pkt.options()) {
        if (opt.option() == id)
            return &opt;
    }
    return nullptr;
}

Tins::Dot11::option construct_csa(const int channel, int count) {
    // CSA IE: switch_mode(1), new_chan(1), switch_count(1)
    vector<uint8_t> data = {
        0x01,                          // switch mode: no Tx until switch
        static_cast<uint8_t>(channel),
        static_cast<uint8_t>(count)
    };
    return Tins::Dot11::option(IEEE_TLV_TYPE_CSA, data.begin(), data.end());
}

Tins::Dot11Beacon* append_csa(const Tins::Dot11Beacon& beacon, int channel, int count) {
    auto* copy = beacon.clone();
    copy->add_option(construct_csa(channel, count));
    return copy;
}

Tins::Dot11ProbeResponse* beacon_to_probe_resp(const Tins::Dot11Beacon& beacon) {
    auto* resp = new Tins::Dot11ProbeResponse();
    resp->addr2(beacon.addr2());
    resp->addr3(beacon.addr3());
    resp->timestamp(0xAAAAAAAAAAAAAAAAULL);
    resp->interval(beacon.interval());
    resp->capabilities() = beacon.capabilities();


    // Copy all IEs except TIM
    for (const auto& opt : beacon.options()) {
        if (opt.option() != IEEE_TLV_TYPE_TIM)
            resp->add_option(opt);
    }
    return resp;
}

vector<uint8_t> find_network(const string& iface,
                                  const string& ssid,
                                  int timeout_ms) {
    log(wpa3_tester::LogLevel::INFO, "Searching for target network...");

    vector channels = {0, 1, 6, 11, 3, 8, 2, 7, 4, 10, 5, 9};

    for (int chan : channels) {
        if (chan != 0)
            set_channel(iface, chan);

        Tins::SnifferConfiguration cfg;
        cfg.set_filter("wlan type mgt subtype beacon");
        cfg.set_timeout(timeout_ms);

        try {
            Tins::Sniffer sniffer(iface, cfg);
            vector<uint8_t> found;

            sniffer.sniff_loop([&](Tins::PDU& pdu) -> bool {
                auto* beacon = pdu.find_pdu<Tins::Dot11Beacon>();
                if (!beacon) return true;
                if (get_ssid(*beacon) == ssid) {
                    found = beacon->serialize();
                    return false;
                }
                return true;
            });

            if (!found.empty()) {
                log(wpa3_tester::LogLevel::DEBUG, "Found beacon on channel " + to_string(chan));
                return found;
            }
        } catch (...) {}
    }

    return {};
}

// ---------------------------------------------------------------------------
// EAPOL helpers
// ---------------------------------------------------------------------------

int get_eapol_msg_num(const Tins::Dot11Data& pkt) {
    // Walk the inner PDU chain looking for raw EAPOL bytes
    const Tins::RawPDU* raw = pkt.find_pdu<Tins::RawPDU>();
    if (!raw || raw->payload().size() < 99) return 0;

    const auto& data = raw->payload();
    // Offset 5-6 in EAPOL body = Key Information field
    const uint16_t flags = (static_cast<uint16_t>(data[5]) << 8) | data[6];

    if (!(flags & EAPOL_FLAG_PAIRWISE)) return 0;

    if (flags & EAPOL_FLAG_ACK) {
        return (flags & EAPOL_FLAG_SECURE) ? 3 : 1;
    } else {
        const uint16_t keydatalen = (static_cast<uint16_t>(data[97]) << 8) | data[98];
        return (keydatalen == 0) ? 4 : 2;
    }
}

uint64_t get_eapol_replay_num(const Tins::Dot11Data& pkt) {
    const Tins::RawPDU* raw = pkt.find_pdu<Tins::RawPDU>();
    if (!raw || raw->payload().size() < 17) return 0;

    const auto& data = raw->payload();
    uint64_t val = 0;
    for (int i = 0; i < 8; i++)
        val = (val << 8) | data[9 + i];
    return val;
}
