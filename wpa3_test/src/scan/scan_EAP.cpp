#include <chrono>
#include <map>
#include <set>
#include <tins/rawpdu.h>
#include <tins/sniffer.h>
#include <sys/poll.h>

#include "attacks/components/sniffer_helper.h"
#include "logger/log.h"

using namespace std;
using namespace chrono;
using namespace Tins;

namespace wpa3_tester::scan {

    struct EAP_Info {
        uint8_t code = 0;
        optional<string> identity;
        optional<string> method;
        uint8_t type_code = 0;
    };

    enum class AuthStatus {
        UNKNOWN,
        IN_PROGRESS,
        SUCCESS,
        FAILED
    };

    struct EAP_Session {
        set<string> identities;
        set<string> methods;
        AuthStatus status = AuthStatus::UNKNOWN;
        uint8_t last_type_code = 0;
        steady_clock::time_point last_seen;
        
        string to_str() const;
    };

    string EAP_Session::to_str() const {
        stringstream ss;
        ss << "IDs: ";
        for (auto const& id : identities) ss << id << " ";
        ss << "| Methods: ";
        for (auto const& m : methods) ss << m << " ";
        return ss.str();
    }

    string extract_identity(const vector<uint8_t>& payload) {
        if (payload.size() <= 5) return "Empty"; // (Code, ID, LenH, LenL, Type, [Data...])
        return string(payload.begin() + 5, payload.end());
    }

    EAP_Info parse_eap_packet(const RawPDU& raw) {
        const auto& payload = raw.payload();
        EAP_Info info;

        if (payload.size() < 5) return info;

        info.code = payload[0];

        // Success (3) a Failure (4) has no other info
        if (info.code == 3 || info.code == 4) {return info;}

        const uint8_t type = payload[4];
        info.type_code = type;

        switch (type) {
            case 1:   info.identity = extract_identity(payload); break;
            case 4:   info.method = "EAP-MD5"; break;
            case 6:   info.method = "EAP-GTC"; break;
            case 13:  info.method = "EAP-TLS"; break;
            case 17:  info.method = "EAP-LEAP"; break;
            case 18:  info.method = "EAP-SIM"; break;
            case 21:  info.method = "EAP-TTLS"; break;
            case 23:  info.method = "EAP-AKA"; break;
            case 25:  info.method = "EAP-PEAP"; break;
            case 26:  info.method = "EAP-MSCHAPv2"; break;
            case 29:  info.method = "EAP-POTP"; break;
            case 33:  info.method = "EAP-FAST"; break;
            case 40:  info.method = "EAP-EKE"; break;
            case 43:  info.method = "EAP-TEAP"; break;
            case 50:  info.method = "EAP-AKA-PRIME"; break;
            case 52:  info.method = "EAP-PWD"; break;
            case 254: info.method = "Expanded-Type"; break;
            default:  info.method = "Unknown-" + to_string(type); break;
        }
        if (type == 254 && payload.size() >= 12) {
            // bytes 5-7: Vendor-Id
            // bytes 8-11: Vendor-Type
            info.method = "Expanded-Method (Vendor: " + to_string(payload[5]) + ")";
        }
        return info;
    }

    static optional<monostate> handle_eap_pdu(
        PDU& pdu,
        const string& target_ap_mac,
        map<string, EAP_Session>& sessions)
    {
        const auto* dot11_data = pdu.find_pdu<Dot11Data>();
        const auto* raw        = pdu.find_pdu<RawPDU>();
        if (!dot11_data || !raw) return nullopt;

        const string addr1 = dot11_data->addr1().to_string();
        const string addr2 = dot11_data->addr2().to_string();
        const string client_mac = (addr1 == target_ap_mac) ? addr2 : addr1;

        const EAP_Info info = parse_eap_packet(*raw);

        auto& session = sessions[client_mac];
        session.last_seen      = steady_clock::now();
        session.last_type_code = info.type_code;

        if (info.identity && session.identities.insert(*info.identity).second)
            log(LogLevel::INFO, "[*] New Identity for " + client_mac + ": " + *info.identity);

        if (info.method && session.methods.insert(*info.method).second)
            log(LogLevel::INFO, "[+] New Method for " + client_mac + ": " + *info.method);

        switch (info.code) {
            case 1: // Request
            case 2: // Response
                if (session.status == AuthStatus::UNKNOWN)
                    session.status = AuthStatus::IN_PROGRESS;
                break;
            case 3: // SUCCESS
                if (session.status != AuthStatus::SUCCESS) {
                    session.status = AuthStatus::SUCCESS;
                    log(LogLevel::INFO, "[OK] Auth SUCCESS: Client " + client_mac + " is now CONNECTED.");
                }
                break;
            case 4: // FAILURE
                if (session.status != AuthStatus::FAILED) {
                    session.status = AuthStatus::FAILED;
                    log(LogLevel::INFO, "[!] Auth FAILURE: Client " + client_mac + " was REJECTED.");
                }
                break;
            default:
                throw runtime_error("Unknown EAP code: " + to_string(info.code));
        }

        return nullopt; // until timeout
    }

    void active_eap_identity_scan(const string& iface, const string& target_ap_mac, const int timeout_sec) {
        map<string, EAP_Session> sessions;
        const string filter = "";
        components::poll_sniffer_pdu<monostate>(
            [&](PDU& pdu) { return handle_eap_pdu(pdu, target_ap_mac, sessions); },
            iface, filter, timeout_sec);
    }
}
