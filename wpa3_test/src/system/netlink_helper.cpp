#include "system/netlink_helper.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstring>
#include <expected>
#include <nl80211.h>
#include <system_error>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

namespace wpa3_tester::netlink_helper {

using Result = std::expected<void, std::error_code>;

namespace {

struct IftypeResult {
    nl80211_iftype iftype = NL80211_IFTYPE_UNSPECIFIED;
    bool           found  = false;
};

int parse_iftype_cb(nl_msg *msg, void *arg) {
    auto *result = static_cast<IftypeResult *>(arg);

    const auto *hdr = static_cast<genlmsghdr *>(nlmsg_data(nlmsg_hdr(msg)));
    nlattr *tb[NL80211_ATTR_MAX + 1]{};

    if (nla_parse(tb, NL80211_ATTR_MAX,
                  genlmsg_attrdata(hdr, 0),
                  genlmsg_attrlen(hdr, 0),
                  nullptr) < 0)
        return NL_SKIP;

    if (!tb[NL80211_ATTR_IFTYPE]) return NL_SKIP;

    result->iftype = static_cast<nl80211_iftype>(nla_get_u32(tb[NL80211_ATTR_IFTYPE]));
    result->found  = true;
    return NL_OK;
}

nl80211_iftype query_wifi_iftype(const char *iface_name) {
    nl_sock *sock = nl_socket_alloc();
    if (!sock) return NL80211_IFTYPE_UNSPECIFIED;

    auto cleanup = [&] { nl_socket_free(sock); };

    if (genl_connect(sock) < 0)                        { cleanup(); return NL80211_IFTYPE_UNSPECIFIED; }
    const int nl80211_id = genl_ctrl_resolve(sock, "nl80211");
    if (nl80211_id < 0)                                { cleanup(); return NL80211_IFTYPE_UNSPECIFIED; }
    const unsigned int ifindex = if_nametoindex(iface_name);
    if (ifindex == 0)                                  { cleanup(); return NL80211_IFTYPE_UNSPECIFIED; }

    nl_msg *msg = nlmsg_alloc();
    if (!msg)                                          { cleanup(); return NL80211_IFTYPE_UNSPECIFIED; }

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id, 0, 0, NL80211_CMD_GET_INTERFACE, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);

    IftypeResult result{};
    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, parse_iftype_cb, &result);

    if (nl_send_auto(sock, msg) < 0) {
        nlmsg_free(msg);
        cleanup();
        return NL80211_IFTYPE_UNSPECIFIED;
    }
    nlmsg_free(msg);
    nl_recvmsgs_default(sock);
    cleanup();

    return result.found ? result.iftype : NL80211_IFTYPE_UNSPECIFIED;
}

[[nodiscard]] bool iface_is_up(const std::string_view iface_name) {
    ifreq ifr{};
    iface_name.copy(ifr.ifr_name, IFNAMSIZ - 1);

    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    const bool up = (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) && ((ifr.ifr_flags & IFF_UP) != 0);
    close(fd);
    return up;
}

} // anonymous namespace

int open_rtnetlink() {
    const int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return -1;

    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK;

    if (bind(fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

Result wait_for_link_flags(const int nl_fd, const std::string_view iface_name, const bool want_up) {
    // Fast path: already in the desired state
    if (iface_is_up(iface_name) == want_up) return Result{};

    char buf[8192];
    while (true) {
        ssize_t n = recv(nl_fd, buf, sizeof(buf), 0);
        if (n < 0)
            return std::unexpected(std::make_error_code(std::errc::io_error));

        for (auto *nh = reinterpret_cast<nlmsghdr *>(buf);
             NLMSG_OK(nh, static_cast<size_t>(n));
             nh = NLMSG_NEXT(nh, n))
        {
            if (nh->nlmsg_type != RTM_NEWLINK) continue;

            const auto *ifi = reinterpret_cast<ifinfomsg *>(NLMSG_DATA(nh));

            char name[IF_NAMESIZE];
            if (!if_indextoname(ifi->ifi_index, name)) continue;
            if (std::string_view{name} != iface_name) continue;

            const bool is_up = (ifi->ifi_flags & IFF_UP) != 0;
            if (want_up == is_up) return Result{};
        }
    }
}

Result wait_for_iface_appear(const int nl_fd, const std::string_view iface_name) {
    // Fast path: interface already exists
    if (if_nametoindex(iface_name.data()) != 0) return Result{};

    char buf[8192];
    while (true) {
        ssize_t n = recv(nl_fd, buf, sizeof(buf), 0);
        if (n < 0)
            return std::unexpected(std::make_error_code(std::errc::io_error));

        for (auto *nh = reinterpret_cast<nlmsghdr *>(buf);
             NLMSG_OK(nh, static_cast<size_t>(n));
             nh = NLMSG_NEXT(nh, n))
        {
            if (nh->nlmsg_type != RTM_NEWLINK) continue;

            const auto *ifi = reinterpret_cast<ifinfomsg *>(NLMSG_DATA(nh));
            auto       *rta = IFLA_RTA(ifi);
            int        rlen = static_cast<int>(IFLA_PAYLOAD(nh));

            for (; RTA_OK(rta, rlen); rta = RTA_NEXT(rta, rlen)) {
                if (rta->rta_type != IFLA_IFNAME) continue;
                if (std::string_view{static_cast<const char *>(RTA_DATA(rta))} == iface_name)
                    return Result{};
            }
        }
    }
}

Result wait_for_wifi_iftype(const std::string_view iface_name,
                            const nl80211_iftype expected_type,
                            const int max_retries,
                            const int retry_ms)
{
    for (int i = 0; i < max_retries; ++i) {
        if (query_wifi_iftype(iface_name.data()) == expected_type)
            return Result{};
        usleep(static_cast<useconds_t>(retry_ms) * 1000u);
    }
    return std::unexpected(std::make_error_code(std::errc::timed_out));
}

} // namespace wpa3_tester::netlink_helper