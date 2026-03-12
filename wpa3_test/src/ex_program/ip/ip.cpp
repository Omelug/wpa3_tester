#include "ex_program/ip/ip.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/socket.h>

#include "observer/observers.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::ip{
    using namespace std;
    void set_ip(RunStatus& run_status, const string &actor_name){
        vector<string> command = {"sudo"};
        observer::add_nets(run_status,command, actor_name);
        command.insert(command.end(), {
            "ip", "addr","add",
            run_status.config.at("actors").at(actor_name).at("ip_addr").get<string>() + "/24",
            "dev",run_status.get_actor(actor_name)["iface"]
        });
         hw_capabilities::run_cmd(command);
    }

    string resolve_host(const string& hostname) {
        addrinfo hints{}, *res;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0){
            throw runtime_error("Cannot resolve: " + hostname);
        }
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(res->ai_addr)->sin_addr, ip, sizeof(ip));
        freeaddrinfo(res);
        return string(ip);
    }

    string get_ip(const string& iface) { //TODO tests with  hwhsim
        ifaddrs *ifaddr = nullptr;
        if (getifaddrs(&ifaddr) == -1) {throw runtime_error("Failed to get interface addresses");}

        string ip_address;
        for (const ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) continue;

            if (string(ifa->ifa_name) == iface && ifa->ifa_addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                const void* addr = &(reinterpret_cast<sockaddr_in*>(ifa->ifa_addr)->sin_addr);
                inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN);
                ip_address = string(ip);
                break;
            }
        }

        freeifaddrs(ifaddr);
        if (ip_address.empty()) {throw runtime_error("No IP address found for interface: " + iface);}
        return ip_address;
    }
}
