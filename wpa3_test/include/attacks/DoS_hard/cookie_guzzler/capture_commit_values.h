#pragma once
#include <libtins-src/include/tins/dot11/sae_dot11_auth.h>
#include <tins/hw_address.h>
#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "logger/log.h"

namespace Tins{
    class RawPDU;
    class Dot11Authentication;
}

using namespace std;
using namespace Tins;
namespace wpa3_tester::cookie_guzzler{
    struct SAECallback {
        SAEPair &result;
        atomic<bool> &running;

        /*bool operator()(Packet& packet){
            // 1. Získání surového bufferu přímo z Packet objektu
            // Ten obsahuje VŠECHNO, co přišlo z pcapu, bez ohledu na parser libtins
            PDU::serialization_type buffer = packet.pdu()->serialize();

            std::cout << "Skutečná délka v C++: " << buffer.size() << " bytes" << std::endl;

            if (buffer.size() > 60) {
                // Tady začíná tvůj SAE payload (Group ID 19 = 13 00)
                // Podle tvého dumpu je '13 00' na offsetu 58 (0x3A)
                // Pozor: offset se může lišit podle délky RadioTapu!

                // Najdeme '13 00' sekvenci (Group ID)
                for (size_t i = 30; i < buffer.size() - 2; ++i) {
                    if (buffer[i] == 0x13 && buffer[i+1] == 0x00) {
                        std::cout << "SAE Group ID nalezeno na offsetu: " << i << std::endl;
                        // Tady si můžeš vykopírovat Scalar a Element
                        // Scalar = buffer[i+2] až [i+33]
                        // Element = buffer[i+34] až [i+97]
                        break;
                    }
                }
            }
            return true;
        }*/
    };
    optional<SAEPair> parse_sae_commit(const uint8_t *packet, const uint32_t len);
    SAEPair capture_sae_commit(const std::string &iface, const HWAddress<6> &ap_mac, int timeout_sec);
    void start_wpa_supplicant(const string &iface, const string &conf_path, const string &pid_file);
    void stop_wpa_supplicant(const string &pid_file);
}
