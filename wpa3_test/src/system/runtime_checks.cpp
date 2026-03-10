#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <cstring>
#include <unistd.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sys/ioctl.h>


#include "system/hw_capabilities.h"

namespace wpa3_tester{
    bool check_injection_runtime(const std::string& iface_name) {
        const ActorConfig_iface_func ifc{iface_name, std::nullopt};
        ifc.set_monitor_mode();
        std::this_thread::sleep_for(std::chrono::seconds(5));

        const int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock < 0) return false;

        ifreq ifr = {};
        strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ);

        if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { close(sock); return false; }

        sockaddr_ll sa = {};
        sa.sll_family = AF_PACKET;
        sa.sll_ifindex = ifr.ifr_ifindex;
        sa.sll_protocol = htons(ETH_P_ALL);

        // 802.11 Null-Data s with empty Radiotap  (8 byte RT + 24 byte Dot11)
        uint8_t test_frame[] = {
            0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // Radiotap (v0, length 8)
            0x04, 0x00, 0x00, 0x00,                         // Frame Control (Null Function), Duration
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,             // Dest (Broadcast)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // Source (Dummy)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // BSSID (Dummy)
            0x00, 0x00                                      // Sequence Control
        };

        const ssize_t sent = sendto(sock, test_frame, sizeof(test_frame), 0,
                              reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa));

        close(sock);
        // return bytes send -> injection
        // -1 and errno EOPNOTSUPP or EPERM -> injection blocked
        return (sent > 0);
    }
}
