#include "system/netlink_helper.h"
#include <nl80211.h>
#include <unistd.h>
#include <chrono>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <unordered_set>
#include <vector>
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "system/netlink_guards.h"

using namespace std;

namespace wpa3_tester::netlink_helper{
struct IftypeResult{
	nl80211_iftype iftype = NL80211_IFTYPE_UNSPECIFIED;
	bool found = false;
};

int parse_iftype_cb(nl_msg *msg, void *arg){
	auto *result = static_cast<IftypeResult *>(arg);

	const auto *hdr = static_cast<genlmsghdr *>(nlmsg_data(nlmsg_hdr(msg)));
	nlattr *tb[NL80211_ATTR_MAX + 1]{};

	if(nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(hdr, 0), genlmsg_attrlen(hdr, 0), nullptr) < 0) return NL_SKIP;

	if(!tb[NL80211_ATTR_IFTYPE]) return NL_SKIP;

	result->iftype = static_cast<nl80211_iftype>(nla_get_u32(tb[NL80211_ATTR_IFTYPE]));
	result->found = true;
	return NL_OK;
}

nl80211_iftype query_wifi_iftype(const string_view iface_name, const optional<string> &netns){
	NetNSContext ns_guard(netns);

	const unique_ptr<nl_sock,void(*)(nl_sock *)> sock(nl_socket_alloc(), nl_socket_free);
	if(!sock || genl_connect(sock.get()) < 0) return NL80211_IFTYPE_UNSPECIFIED;

	const int nl80211_id = genl_ctrl_resolve(sock.get(), "nl80211");
	const unsigned int ifindex = if_nametoindex(iface_name.data());
	if(nl80211_id < 0 || ifindex == 0) return NL80211_IFTYPE_UNSPECIFIED;

	const unique_ptr<nl_msg,void(*)(nl_msg *)> msg(nlmsg_alloc(), nlmsg_free);
	if(!msg) return NL80211_IFTYPE_UNSPECIFIED;

	(void)genlmsg_put(msg.get(), NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id, 0, 0, NL80211_CMD_GET_INTERFACE, 0);
	(void)nla_put_u32(msg.get(), NL80211_ATTR_IFINDEX, ifindex);

	IftypeResult result{};
	nl_socket_modify_cb(sock.get(), NL_CB_VALID, NL_CB_CUSTOM, parse_iftype_cb, &result);
	if(nl_send_auto(sock.get(), msg.get()) >= 0) nl_recvmsgs_default(sock.get());

	return result.found ? result.iftype : NL80211_IFTYPE_UNSPECIFIED;
}

[[nodiscard]] static optional<uint32_t> get_iface_flags(const string_view iface_name, const optional<string> &netns){
	NetNSContext ns_guard(netns);
	const int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) return nullopt;

	ifreq ifr{};
	iface_name.copy(ifr.ifr_name, IFNAMSIZ - 1);

	if(ioctl(sock, SIOCGIFFLAGS, &ifr) < 0){
		close(sock);
		return nullopt;
	}
	close(sock);
	return static_cast<uint32_t>(ifr.ifr_flags);
}

// up correctly
[[nodiscard]] bool iface_is_up(const string_view iface_name, const optional<string> &netns){
	return get_iface_flags(iface_name, netns).transform([](const short f){
		return (f & IFF_UP) != 0 /*&& (f & IFF_RUNNING) != 0*/;
	}).value_or(false);
}

// down correctly
[[nodiscard]] bool iface_is_down(const string_view iface_name, const optional<string> &netns){
	return get_iface_flags(iface_name, netns).transform([](const short f){
		return (f & (IFF_UP)) == 0;
	}).value_or(false);
}

Result wait_for_link_flags(const string_view iface_name, const optional<string> &netns, const bool want_up,
							const int timeout_ms
){
	//already in correct state
	if(want_up && iface_is_up(iface_name, netns)) return {};
	if(!want_up && iface_is_down(iface_name, netns)) return {};
	NetNSContext ns_guard(netns);

	const timeval tv{.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
	(void)setsockopt(NetlinkRegistry::get_fd(netns), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	char buf[8192];
	while(true){
		ssize_t n = recv(NetlinkRegistry::get_fd(netns), buf, sizeof(buf), 0);
		if(n < 0){
			if(errno == EAGAIN || errno == EWOULDBLOCK) return make_error_code(errc::timed_out);
			return make_error_code(errc::io_error);
		}

		for(auto *nh = reinterpret_cast<nlmsghdr *>(buf); NLMSG_OK(nh, static_cast<size_t>(n)); nh = NLMSG_NEXT(nh, n)){
			if(nh->nlmsg_type != RTM_NEWLINK) continue;

			const auto *ifi = static_cast<ifinfomsg *>(NLMSG_DATA(nh));

			char name[IF_NAMESIZE];
			if(!if_indextoname(ifi->ifi_index, name)) continue;
			if(string_view{name} != iface_name) continue;

			const auto f = static_cast<unsigned int>(ifi->ifi_flags);
			const bool is_up = (f & IFF_UP) /*&& (f & IFF_RUNNING)*/;
			const bool is_down = (f & IFF_UP) == 0;

			if(want_up && is_up) return {};
			if(!want_up && is_down) return {};
		}
	}
}

// netlink_helper.cpp
Result wait_for_iface_disappear(const string_view iface_name, const optional<string> &netns){
	NetNSContext ns_guard(netns);
	// Fast path: interface already gone
	char name[IF_NAMESIZE]{};
	iface_name.copy(name, IF_NAMESIZE - 1);
	if(if_nametoindex(name) == 0) return {};

	char buf[8192];
	while(true){
		ssize_t n = recv(NetlinkRegistry::get_fd(netns), buf, sizeof(buf), 0);
		if(n < 0) return make_error_code(errc::io_error);

		for(auto *nh = reinterpret_cast<nlmsghdr *>(buf); NLMSG_OK(nh, static_cast<size_t>(n)); nh = NLMSG_NEXT(nh, n)){
			if(nh->nlmsg_type != RTM_DELLINK) continue;

			const auto *ifi = static_cast<ifinfomsg *>(NLMSG_DATA(nh));
			auto *rta = IFLA_RTA(ifi);
			int rlen = static_cast<int>(IFLA_PAYLOAD(nh));

			for(; RTA_OK(rta, rlen); rta = RTA_NEXT(rta, rlen)){
				if(rta->rta_type != IFLA_IFNAME) continue;
				if(string_view{static_cast<const char *>(RTA_DATA(rta))} == iface_name) return {};
			}
		}
	}
}

Result wait_for_iface_appear(const string_view iface_name, const optional<string> &netns, const int timeout_ms){
	NetNSContext ns_guard(netns);
	// Fast path: interface already exists
	char name[IF_NAMESIZE]{};
	iface_name.copy(name, IF_NAMESIZE - 1);
	if(if_nametoindex(name) != 0) return {};

	const timeval tv{.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
	(void)setsockopt(NetlinkRegistry::get_fd(netns), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	char buf[8192];
	while(true){
		ssize_t n = recv(NetlinkRegistry::get_fd(netns), buf, sizeof(buf), 0);
		if(n < 0){
			if(errno == EAGAIN || errno == EWOULDBLOCK) return make_error_code(errc::timed_out);
			return make_error_code(errc::io_error);
		}

		for(auto *nh = reinterpret_cast<nlmsghdr *>(buf); NLMSG_OK(nh, static_cast<size_t>(n)); nh = NLMSG_NEXT(nh, n)){
			if(nh->nlmsg_type != RTM_NEWLINK) continue;

			const auto *ifi = static_cast<ifinfomsg *>(NLMSG_DATA(nh));
			auto *rta = IFLA_RTA(ifi);
			int rlen = static_cast<int>(IFLA_PAYLOAD(nh));

			for(; RTA_OK(rta, rlen); rta = RTA_NEXT(rta, rlen)){
				if(rta->rta_type != IFLA_IFNAME) continue;
				if(string_view{static_cast<const char *>(RTA_DATA(rta))} == iface_name) return {};
			}
		}
	}
}

Result wait_for_wifi_iftype(const string_view iface_name, const optional<string> &netns,
							const nl80211_iftype expected_type, const int max_retries, const int retry_ms
){
	for(int i = 0; i < max_retries; ++i){
		if(query_wifi_iftype(iface_name.data(), netns) == expected_type) return {};
		usleep(static_cast<useconds_t>(retry_ms) * 1000u);
	}
	return make_error_code(errc::timed_out);
}

struct FreqResult{
	uint32_t freq = 0;
	bool found = false;
};

static int parse_freq_cb(nl_msg *msg, void *arg){
	auto *result = static_cast<FreqResult *>(arg);

	const auto *hdr = static_cast<genlmsghdr *>(nlmsg_data(nlmsg_hdr(msg)));
	nlattr *tb[NL80211_ATTR_MAX + 1]{};

	if(nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(hdr, 0), genlmsg_attrlen(hdr, 0), nullptr) < 0) return NL_SKIP;
	if(!tb[NL80211_ATTR_WIPHY_FREQ]) return NL_SKIP;

	result->freq = nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]);
	result->found = true;
	return NL_OK;
}

static uint32_t query_iface_freq(const string_view iface_name, const optional<string> &netns){
	NetNSContext ns_guard(netns);

	const unique_ptr<nl_sock,void(*)(nl_sock *)> sock(nl_socket_alloc(), nl_socket_free);
	if(!sock || genl_connect(sock.get()) < 0) return 0;

	const int nl80211_id = genl_ctrl_resolve(sock.get(), "nl80211");
	const unsigned int ifindex = if_nametoindex(iface_name.data());
	if(nl80211_id < 0 || ifindex == 0) return 0;

	const unique_ptr<nl_msg,void(*)(nl_msg *)> msg(nlmsg_alloc(), nlmsg_free);
	if(!msg) return 0;

	(void)genlmsg_put(msg.get(), NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id, 0, 0, NL80211_CMD_GET_INTERFACE, 0);
	(void)nla_put_u32(msg.get(), NL80211_ATTR_IFINDEX, ifindex);

	FreqResult result{};
	nl_socket_modify_cb(sock.get(), NL_CB_VALID, NL_CB_CUSTOM, parse_freq_cb, &result);
	if(nl_send_auto(sock.get(), msg.get()) >= 0) nl_recvmsgs_default(sock.get());

	return result.found ? result.freq : 0;
}

Result wait_for_channel(const string_view iface_name, const optional<string> &netns, const Channel &ch,
						const int max_retries, const int retry_ms
){
	const auto expected_freq = static_cast<uint32_t>(hw_capabilities::channel_to_freq(ch));
	for(int i = 0; i < max_retries; ++i){
		if(query_iface_freq(iface_name, netns) == expected_freq) return {};
		usleep(static_cast<useconds_t>(retry_ms) * 1000u);
	}
	return make_error_code(errc::timed_out);
}

Result set_channel_nl(const string_view iface, const optional<string> &netns, const Channel &ch){
	NetNSContext ns_guard(netns);

	const unique_ptr<nl_sock,void(*)(nl_sock *)> sock(nl_socket_alloc(), nl_socket_free);
	if(!sock || genl_connect(sock.get()) < 0) return make_error_code(errc::io_error);

	nl_socket_set_buffer_size(sock.get(), 8192, 8192);

	const int nl80211_id = genl_ctrl_resolve(sock.get(), "nl80211");
	if(nl80211_id < 0) return make_error_code(errc::no_such_device);

	const unsigned int ifindex = if_nametoindex(iface.data());
	if(ifindex == 0) return make_error_code(errc::no_such_device);

	const unique_ptr<nl_msg,void(*)(nl_msg *)> msg(nlmsg_alloc(), nlmsg_free);
	if(!msg) return make_error_code(errc::not_enough_memory);

	const auto freq = static_cast<uint32_t>(hw_capabilities::channel_to_freq(ch));

	uint32_t chan_width = NL80211_CHAN_WIDTH_20_NOHT;
	uint32_t center1   = freq;
	if(ch.ht_mode){
		if(*ch.ht_mode == "HT40+" || *ch.ht_mode == "HT40"){ chan_width = NL80211_CHAN_WIDTH_40; center1 = freq + 10; }
		else if(*ch.ht_mode == "HT40-"){                      chan_width = NL80211_CHAN_WIDTH_40; center1 = freq - 10; }
		else if(*ch.ht_mode == "HT20"){                       chan_width = NL80211_CHAN_WIDTH_20; }
	}

	// NL80211_CMD_SET_CHANNEL updates the wdev's chandef (visible in `iw dev info`).
	// NL80211_CMD_SET_WIPHY only updates the PHY-level default; on some kernels
	// (e.g. RPi 6.x) that is not reflected per-wdev in `iw dev info`.
	(void)genlmsg_put(msg.get(), NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id, 0, 0, NL80211_CMD_SET_CHANNEL, 0);
	(void)nla_put_u32(msg.get(), NL80211_ATTR_IFINDEX, ifindex);
	(void)nla_put_u32(msg.get(), NL80211_ATTR_WIPHY_FREQ, freq);
	(void)nla_put_u32(msg.get(), NL80211_ATTR_CHANNEL_WIDTH, chan_width);
	(void)nla_put_u32(msg.get(), NL80211_ATTR_CENTER_FREQ1, center1);

	int err = 0;
	// ReSharper disable once CppParameterMayBeConstPtrOrRef
	nl_socket_modify_err_cb(sock.get(), NL_CB_CUSTOM, [](sockaddr_nl *, nlmsgerr *e, void *arg) ->int{
		*static_cast<int *>(arg) = e->error;
		return NL_STOP;
	}, &err);

	if(nl_send_auto(sock.get(), msg.get()) < 0) return make_error_code(errc::io_error);

	nl_recvmsgs_default(sock.get());

	if(err < 0) return {-err, system_category()};
	return {};
}

void delete_ns_and_wait(const string &ns_name, const vector<string> &ifaces,
                        const chrono::milliseconds timeout)
{
	const string ns_path = "/var/run/netns/" + ns_name;

	// Open and bind netlink socket BEFORE touching the ns — umount2 alone can
	// drop the last reference and immediately return interfaces to root ns,
	// firing RTM_NEWLINK before we'd have a chance to subscribe.
	const int nl_fd = ifaces.empty() ? -1 : socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
	if(!ifaces.empty()){
		if(nl_fd < 0){
			log(LogLevel::WARNING, "netlink socket failed: {}", strerror(errno));
		} else{
			sockaddr_nl sa{};
			sa.nl_family = AF_NETLINK;
			sa.nl_groups = RTMGRP_LINK;
			if(bind(nl_fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) != 0){
				log(LogLevel::WARNING, "netlink bind failed: {}", strerror(errno));
				close(nl_fd);
			}
		}
	}

	if(umount2(ns_path.c_str(), MNT_DETACH) != 0)
		log(LogLevel::WARNING, "umount2 {} failed: {}", ns_path, strerror(errno));

	if(unlink(ns_path.c_str()) != 0)
		log(LogLevel::WARNING, "unlink {} failed: {}", ns_path, strerror(errno));

	if(ifaces.empty() || nl_fd < 0){
		if(nl_fd >= 0) close(nl_fd);
		return;
	}

	unordered_set waiting(ifaces.begin(), ifaces.end());
	for(auto it = waiting.begin(); it != waiting.end();)
		filesystem::exists("/sys/class/net/" + *it) ? it = waiting.erase(it) : ++it;

	const auto deadline = chrono::steady_clock::now() + timeout;
	char buf[8192];

	while(!waiting.empty() && chrono::steady_clock::now() < deadline){
		pollfd pfd{nl_fd, POLLIN, 0};
		const auto remaining = chrono::duration_cast<chrono::milliseconds>(deadline - chrono::steady_clock::now());
		if(remaining.count() <= 0) break;
		if(poll(&pfd, 1, static_cast<int>(remaining.count())) <= 0) break;

		ssize_t len = recv(nl_fd, buf, sizeof(buf), 0);
		if(len <= 0) continue;

		for(auto *nh = reinterpret_cast<nlmsghdr *>(buf);
			NLMSG_OK(nh, static_cast<uint32_t>(len)); nh = NLMSG_NEXT(nh, len))
		{
			if(nh->nlmsg_type != RTM_NEWLINK) continue;

			int attr_len = static_cast<int>(nh->nlmsg_len - NLMSG_SPACE(sizeof(ifinfomsg)));
			auto *attr = reinterpret_cast<rtattr *>(
				static_cast<char *>(NLMSG_DATA(nh)) + NLMSG_ALIGN(sizeof(ifinfomsg)));

			while(RTA_OK(attr, attr_len)){
				if(attr->rta_type == IFLA_IFNAME){
					const string name = static_cast<char *>(RTA_DATA(attr));
					if(waiting.contains(name) &&
						filesystem::exists("/sys/class/net/" + name)){
						log(LogLevel::DEBUG, "Interface {} returned to root ns", name);
						waiting.erase(name);
					}
				}
				attr = RTA_NEXT(attr, attr_len);
			}
		}
	}
	close(nl_fd);
	for(const auto &name: waiting)
		log(LogLevel::WARNING, "Interface {} did not return to root netns in time", name);
}
}
