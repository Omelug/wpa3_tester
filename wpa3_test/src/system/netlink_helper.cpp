#include "system/netlink_helper.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <expected>
#include <fstream>
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
#include "system/netlink_guards.h"

using namespace std;

namespace wpa3_tester::netlink_helper{
using Result = std::expected<void,std::error_code>;

struct IftypeResult{
    nl80211_iftype iftype = NL80211_IFTYPE_UNSPECIFIED;
    bool found = false;
};

int parse_iftype_cb(nl_msg *msg, void *arg){
    auto *result = static_cast<IftypeResult *>(arg);

    const auto *hdr = static_cast<genlmsghdr *>(nlmsg_data(nlmsg_hdr(msg)));
    nlattr *tb[NL80211_ATTR_MAX + 1]{};

    if(nla_parse(tb, NL80211_ATTR_MAX,
                 genlmsg_attrdata(hdr, 0),
                 genlmsg_attrlen(hdr, 0),
                 nullptr) < 0)
        return NL_SKIP;

    if(!tb[NL80211_ATTR_IFTYPE]) return NL_SKIP;

    result->iftype = static_cast<nl80211_iftype>(nla_get_u32(tb[NL80211_ATTR_IFTYPE]));
    result->found = true;
    return NL_OK;
}

nl80211_iftype query_wifi_iftype(const string_view iface_name, const optional<string>& netns){
    NetNSContext ns_guard(netns);

    const unique_ptr<nl_sock,void(*)(nl_sock *)> sock(nl_socket_alloc(), nl_socket_free);
    if(!sock || genl_connect(sock.get()) < 0) return NL80211_IFTYPE_UNSPECIFIED;

    const int nl80211_id = genl_ctrl_resolve(sock.get(), "nl80211");
    const unsigned int ifindex = if_nametoindex(iface_name.data());
    if(nl80211_id < 0 || ifindex == 0) return NL80211_IFTYPE_UNSPECIFIED;

    const unique_ptr<nl_msg,void(*)(nl_msg *)> msg(nlmsg_alloc(), nlmsg_free);
    if(!msg) return NL80211_IFTYPE_UNSPECIFIED;

    genlmsg_put(msg.get(), NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id, 0, 0, NL80211_CMD_GET_INTERFACE, 0);
    nla_put_u32(msg.get(), NL80211_ATTR_IFINDEX, ifindex);

    IftypeResult result{};
    nl_socket_modify_cb(sock.get(), NL_CB_VALID, NL_CB_CUSTOM, parse_iftype_cb, &result);
    if(nl_send_auto(sock.get(), msg.get()) >= 0) nl_recvmsgs_default(sock.get());

    return result.found ? result.iftype : NL80211_IFTYPE_UNSPECIFIED;
}

[[nodiscard]] static expected<uint32_t,error_code> get_iface_flags(string_view iface_name, const optional<string>& netns){
    NetNSContext ns_guard(netns);
    const auto path = format("/sys/class/net/{}/flags", iface_name);
    ifstream f(path);
    if(!f) return unexpected(error_code(errno, system_category()));

    uint32_t flags = 0;
    f >> hex >> flags;
    if(f.fail()) return unexpected(make_error_code(errc::io_error));

    return flags;
}

// up correctly
[[nodiscard]] bool iface_is_up(const string_view iface_name, const optional<string>& netns){
    return get_iface_flags(iface_name, netns).transform([](const short f){
        return (f & IFF_UP) != 0 /*&& (f & IFF_RUNNING) != 0*/;
    }).value_or(false);
}

// down correctly
[[nodiscard]] bool iface_is_down(const string_view iface_name, const optional<string>& netns){
    return get_iface_flags(iface_name, netns).transform([](const short f){
        return (f & (IFF_UP)) == 0;
    }).value_or(false);
}

Result wait_for_link_flags(const string_view iface_name, const optional<string>& netns, const bool want_up,
                           const int timeout_ms){
    //already in correct state
    if(want_up && iface_is_up(iface_name, netns)) return {};
    if(!want_up && iface_is_down(iface_name, netns)) return {};
    NetNSContext ns_guard(netns);

    const timeval tv{.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
    setsockopt(NetlinkRegistry::get_fd(netns), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[8192];
    while(true){
        ssize_t n = recv(NetlinkRegistry::get_fd(netns), buf, sizeof(buf), 0);
        if(n < 0){
            if(errno == EAGAIN || errno == EWOULDBLOCK) return unexpected(make_error_code(errc::timed_out));
            return unexpected(make_error_code(errc::io_error));
        }

        for(auto *nh = reinterpret_cast<nlmsghdr *>(buf);
            NLMSG_OK(nh, static_cast<size_t>(n));
            nh = NLMSG_NEXT(nh, n)){
            if(nh->nlmsg_type != RTM_NEWLINK) continue;

            const auto *ifi = static_cast<ifinfomsg *>(NLMSG_DATA(nh));

            char name[IF_NAMESIZE];
            if(!if_indextoname(ifi->ifi_index, name)) continue;
            if(string_view{name} != iface_name) continue;

            const auto f = static_cast<unsigned int>(ifi->ifi_flags);
            const bool is_up = (f & IFF_UP) && (f & IFF_RUNNING);
            const bool is_down = (f & IFF_UP) == 0;

            if(want_up && is_up) return Result{};
            if(!want_up && is_down) return Result{};
        }
    }
}

// netlink_helper.cpp
Result wait_for_iface_disappear(const string_view iface_name, const optional<string>& netns){
    NetNSContext ns_guard(netns);
    // Fast path: interface already gone
    char name[IF_NAMESIZE]{};
    iface_name.copy(name, IF_NAMESIZE - 1);
    if(if_nametoindex(name) == 0) return Result{};

    char buf[8192];
    while(true){
        ssize_t n = recv(NetlinkRegistry::get_fd(netns), buf, sizeof(buf), 0);
        if(n < 0) return unexpected(make_error_code(errc::io_error));

        for(auto *nh = reinterpret_cast<nlmsghdr *>(buf);
            NLMSG_OK(nh, static_cast<size_t>(n));
            nh = NLMSG_NEXT(nh, n)){
            if(nh->nlmsg_type != RTM_DELLINK) continue;

            const auto *ifi = static_cast<ifinfomsg *>(NLMSG_DATA(nh));
            auto *rta = IFLA_RTA(ifi);
            int rlen = static_cast<int>(IFLA_PAYLOAD(nh));

            for(; RTA_OK(rta, rlen); rta = RTA_NEXT(rta, rlen)){
                if(rta->rta_type != IFLA_IFNAME) continue;
                if(string_view{static_cast<const char *>(RTA_DATA(rta))} == iface_name) return Result{};
            }
        }
    }
}

Result wait_for_iface_appear(const string_view iface_name,  const optional<string>& netns, const int timeout_ms) {
    NetNSContext ns_guard(netns);
    // Fast path: interface already exists
    char name[IF_NAMESIZE]{};
    iface_name.copy(name, IF_NAMESIZE - 1);
    if(if_nametoindex(name) != 0) return Result{};

    const timeval tv{.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
    setsockopt(NetlinkRegistry::get_fd(netns), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[8192];
    while(true){
        ssize_t n = recv(NetlinkRegistry::get_fd(netns), buf, sizeof(buf), 0);
        if(n < 0){
            if(errno == EAGAIN || errno == EWOULDBLOCK) return unexpected(make_error_code(errc::timed_out));
            return unexpected(make_error_code(errc::io_error));
        }

        for(auto *nh = reinterpret_cast<nlmsghdr *>(buf);
            NLMSG_OK(nh, static_cast<size_t>(n));
            nh = NLMSG_NEXT(nh, n)){
            if(nh->nlmsg_type != RTM_NEWLINK) continue;

            const auto *ifi = static_cast<ifinfomsg *>(NLMSG_DATA(nh));
            auto *rta = IFLA_RTA(ifi);
            int rlen = static_cast<int>(IFLA_PAYLOAD(nh));

            for(; RTA_OK(rta, rlen); rta = RTA_NEXT(rta, rlen)){
                if(rta->rta_type != IFLA_IFNAME) continue;
                if(string_view{static_cast<const char *>(RTA_DATA(rta))} == iface_name) return Result{};
            }
        }
    }
}

Result wait_for_wifi_iftype(const string_view iface_name,
                            const optional<string>& netns,
                            const nl80211_iftype expected_type,
                            const int max_retries,
                            const int retry_ms) {
    for(int i = 0; i < max_retries; ++i){
        if(query_wifi_iftype(iface_name.data(), netns) == expected_type) return Result{};
        usleep(static_cast<useconds_t>(retry_ms) * 1000u);
    }
    return unexpected(make_error_code(errc::timed_out));
}

void log_iface_info(const string_view iface_name, const optional<string>& netns){
    NetNSContext ns_guard(netns);
    ifreq ifr{};
    iface_name.copy(ifr.ifr_name, IFNAMSIZ - 1);

    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0){
        fprintf(stderr, "DEBUG iface_info(%.*s): failed to open socket\n",
                static_cast<int>(iface_name.size()), iface_name.data());
        return;
    }
    const bool ok = ioctl(fd, SIOCGIFFLAGS, &ifr) == 0;
    close(fd);

    if(!ok){
        fprintf(stderr, "DEBUG iface_info(%.*s): ioctl failed — interface may not exist\n",
                static_cast<int>(iface_name.size()), iface_name.data());
        return;
    }

    const short f = ifr.ifr_flags;
    fprintf(stderr,
            "DEBUG iface_info(%.*s): UP=%d RUNNING=%d BROADCAST=%d MULTICAST=%d flags=0x%04x\n",
            static_cast<int>(iface_name.size()), iface_name.data(),
            !!(f & IFF_UP),
            !!(f & IFF_RUNNING),
            !!(f & IFF_BROADCAST),
            !!(f & IFF_MULTICAST),
            static_cast<unsigned short>(f));

    const auto iftype = query_wifi_iftype(iface_name.data(), netns);
    const auto *type_str = [&]() ->const char *{
        switch(iftype){
            case NL80211_IFTYPE_STATION: return "managed";
            case NL80211_IFTYPE_MONITOR: return "monitor";
            case NL80211_IFTYPE_AP: return "AP";
            case NL80211_IFTYPE_ADHOC: return "IBSS";
            default: return "unknown";
        }
    }();
    fprintf(stderr, "DEBUG iface_info(%.*s): wifi type=%s (%d)\n",
            static_cast<int>(iface_name.size()), iface_name.data(),
            type_str, static_cast<int>(iftype));
}
}
