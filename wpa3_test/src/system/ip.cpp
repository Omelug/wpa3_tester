#include "system/ip.h"
#include <fcntl.h>
#include <ifaddrs.h>
#include <memory>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "ex_program/external_actors/ExternalConn.h"
#include "logger/error_log.h"
#include "observer/observers.h"
#include "system/hw_capabilities.h"

using namespace std;
namespace wpa3_tester::ip{
void set_ip(RunStatus &rs, const string &actor_name){
	const auto ip_addr = rs.config().at("actors").at(actor_name).at("ip_addr").get<string>();
	const auto actor = rs.get_actor(actor_name);
	if(actor.get()->conn != nullptr){
		rs.get_actor(actor_name).get()->conn->set_ip(actor.get(SK::iface), ip_addr);
	} else{
		vector<string> command = {};
		observer::add_nets_header(rs, command, actor_name);
		command.insert(command.end(), {"ip", "addr", "add", ip_addr + "/24", "dev", actor.get(SK::iface)});
		hw_capabilities::run_cmd(command);
	}
}

string resolve_host(const string &hostname){
	addrinfo hints{}, *raw;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if(getaddrinfo(hostname.c_str(), nullptr, &hints, &raw) != 0)
		throw run_err("Cannot resolve: " + hostname);
	const unique_ptr<addrinfo, decltype(&freeaddrinfo)> res(raw, freeaddrinfo);
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(res->ai_addr)->sin_addr, ip, sizeof(ip));
	return ip;
}

string get_ip(const string &iface){
	ifaddrs *raw = nullptr;
	if(getifaddrs(&raw) == -1) throw run_err("Failed to get interface addresses");
	const unique_ptr<ifaddrs, decltype(&freeifaddrs)> ifaddr(raw, freeifaddrs);

	for(const ifaddrs *ifa = ifaddr.get(); ifa != nullptr; ifa = ifa->ifa_next){
		if(!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
		if(string_view(ifa->ifa_name) != iface) continue;
		char ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in *>(ifa->ifa_addr)->sin_addr, ip, sizeof(ip));
		return ip;
	}
	throw run_err("No IP address found for interface: " + iface);
}

bool ping(const string &ip, const int timeout_sec){
	return hw_capabilities::run_cmd({"ping", "-c", "1", "-n", "-W", to_string(timeout_sec), ip}, nullopt) == 0;
}

/*string get_mac_by_ip(const string &ip){
	// trigger ARP
	ping(ip);
	// default netns
	const string out = hw_capabilities::run_cmd_output({"arp", "-n", ip}, nullopt);
	smatch match;
	if(!regex_search(out, match, regex(R"(([0-9a-f]{2}(?::[0-9a-f]{2}){5}))")))
		throw scan_err("Cannot get MAC for IP: " + ip);
	return match[1].str();
}*/
}