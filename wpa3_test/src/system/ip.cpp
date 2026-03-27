#include "../../include/system/ip.h"

#include <fcntl.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/socket.h>
#include <regex>

#include "ex_program/external_actors/ExternalConn.h"
#include "logger/error_log.h"
#include "observer/observers.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::ip{
    using namespace std;
    void set_ip(RunStatus& run_status, const string &actor_name){
        const auto ip_addr = run_status.config.at("actors").at(actor_name).at("ip_addr").get<string>();
        const auto actor = run_status.get_actor(actor_name);
        if(actor.get()->conn != nullptr){
            run_status.get_actor(actor_name).get()->conn->set_ip(actor["iface"],ip_addr);
        }else{
            vector<string> command = {};
            observer::add_nets(run_status,command, actor_name);
            command.insert(command.end(), {
                "ip", "addr","add",
                ip_addr+"/24",
                "dev", actor["iface"]
            });
            hw_capabilities::run_cmd(command);
        }
    }

    string resolve_host(const string& hostname) {
        addrinfo hints{}, *res;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0){
            throw runtime_error("Cannot resolve: "+hostname);
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
        if (ip_address.empty()) {throw runtime_error("No IP address found for interface: "+iface);}
        return ip_address;
    }

    auto is_port_open(const std::string &ip, int port, const int timeout_ms)->bool{
        const int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;

        fcntl(sock, F_SETFL, O_NONBLOCK);

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        connect(sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));

        pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLOUT;

        const int res = poll(&pfd, 1, timeout_ms);
        bool connected = false;

        if (res > 0) {
            int err;
            socklen_t len = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == 0) connected = true;
        }

        close(sock);
        return connected;
    }

    bool ping(const string& ip, const int timeout_sec) {
        return hw_capabilities::run_cmd(
            {"ping", "-c", "1", "-n","-W", std::to_string(timeout_sec), ip}, nullopt) == 0;
    }

    string get_mac_by_ip(const string& ip) {
        // trigger ARP
        ping(ip);
        const string out = hw_capabilities::run_cmd_output({"arp", "-n", ip});
        smatch match;
        if (!regex_search(out, match, regex(R"(([0-9a-f]{2}(?::[0-9a-f]{2}){5}))")))
            throw scan_err("Cannot get MAC for IP: "+ip);
        return match[1].str();
    }
}
