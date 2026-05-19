#include "system/ip.h"
#include <fcntl.h>
#include <ifaddrs.h>
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
		rs.get_actor(actor_name).get()->conn->set_ip(actor["iface"], ip_addr);
	} else{
		vector<string> command = {};
		observer::add_nets_header(rs, command, actor_name);
		command.insert(command.end(), {"ip", "addr", "add", ip_addr + "/24", "dev", actor["iface"]});
		hw_capabilities::run_cmd(command);
	}
}

string resolve_host(const string &hostname){
	addrinfo hints{}, *res;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if(getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0){
		throw run_err("Cannot resolve: " + hostname);
	}
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(res->ai_addr)->sin_addr, ip, sizeof(ip));
	freeaddrinfo(res);
	return string(ip);
}

string get_ip(const string &iface){
	ifaddrs *ifaddr = nullptr;
	if(getifaddrs(&ifaddr) == -1){ throw run_err("Failed to get interface addresses"); }

	string ip_address;
	for(const ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next){
		if(ifa->ifa_addr == nullptr) continue;

		if(string(ifa->ifa_name) == iface && ifa->ifa_addr->sa_family == AF_INET){
			char ip[INET_ADDRSTRLEN];
			const void *addr = &(reinterpret_cast<sockaddr_in *>(ifa->ifa_addr)->sin_addr);
			inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN);
			ip_address = string(ip);
			break;
		}
	}

	freeifaddrs(ifaddr);
	if(ip_address.empty()){ throw run_err("No IP address found for interface: " + iface); }
	return ip_address;
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