#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>
#include <sys/types.h>
#include <sys/wait.h>
#include <random>

#include "system/hw_capabilities.h"
#include "config/global_config.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"

namespace wpa3_tester{
    using namespace std;
    using namespace filesystem;

    string hw_capabilities::read_sysfs(const string &iface, const string &file){
        const string path = "/sys/class/net/" + iface + "/" + file;

        ifstream ifs(path);
        if(!ifs.is_open()){ throw config_err("read_sysfs failed");}

        string content;
        getline(ifs, content);
        if(!content.empty() && content.back() == '\n') content.pop_back();
        return content;
    }

    string hw_capabilities::get_driver_name(const string &iface){
        const string path = "/sys/class/net/" + iface + "/device/driver";
        try{
            if(filesystem::exists(path) && filesystem::is_symlink(path)){
                return filesystem::read_symlink(path).filename().string();
            }
        } catch(const filesystem::filesystem_error &e){
            throw config_err("Driver check error: " + string(e.what()));
        }
        throw config_err("Driver check error: not found valid symlink"); ;
    }

    string hw_capabilities::get_phy(const string &iface) {
        const path link = "/sys/class/net/" + iface + "/phy80211";
        if (!exists(link)) return "";
        return read_symlink(link).filename().string();
    }

    int get_interface_arphrd_type(const path& iface_path) {
        ifstream file(iface_path / "type");
        int type = 0;
        if (file >> type) return type;
        return 0;
    }

    vector<InterfaceInfo> hw_capabilities::list_interfaces(const optional<InterfaceType> filter){
        vector<InterfaceInfo> result;
        const path net_path = "/sys/class/net";

        if(!exists(net_path)) return result;
        for(const auto &entry: directory_iterator(net_path)){
            string iface = entry.path().filename().string();

            auto ignored_list = get_global_config().at("actors").value("ignore_interfaces", vector<string>{});

            if(set ignored_set(ignored_list.begin(), ignored_list.end()); ignored_set.contains(iface)){
                log(LogLevel::DEBUG, "Ignoring interface "+iface+" due to ignore_interfaces config");
                continue;
            }

            auto type = InterfaceType::Unknown;
            if(iface == "lo"){
                type = InterfaceType::Loopback;  // Loopback ('lo')
            }else if(exists(entry.path() / "wireless") || filesystem::exists(entry.path() / "phy80211")){
                if(iface.rfind(MONITOR_IFACE_PREFIX, 0) == 0) { // start with prefix, not good fix
                    type = InterfaceType::WifiVirtualMon;  // Virtual wireless Wi-Fi (for monitor mode)
                }else{
                    type = InterfaceType::Wifi;   // wireless Wi-Fi
                }

            }else if(exists(entry.path() / "bridge")){
                type = InterfaceType::DockerBridge;  // Docker Bridge ('bridge')
            }else if(exists(entry.path() / "tun_flags")){
                type = InterfaceType::VPN; // VPN / TUN (tun_flags)
            } else if(iface.find("veth") == 0){
                type = InterfaceType::VirtualVeth; // virtual veth docker container etc)
            } else if(exists(entry.path() / "device")){
                type = InterfaceType::Ethernet; // Wire ethernet
            }
            const string radio = get_phy(iface);
            if(filter.has_value()){
                if(filter.value() == type){result.push_back({iface, radio,type});}
            }else{
                result.push_back({iface, radio,type});
            }
        }
        return result;
    }

    // ---------------------- BACKTRACKING ------------------------ Map of (RuleKey -> OptionKey)

    bool hw_capabilities::findSolution(
        const vector<string> &ruleKeys,
        const size_t ruleIdx,
        const ActorCMap &rules,
        const vector<ActorPtr> &options,
        unordered_set<size_t> &usedOptions,
        ActorMap &currentAssignment
    ){
        if (ruleIdx == ruleKeys.size()) return true;

        const string &actor_name = ruleKeys[ruleIdx];
        const auto &ruleIt = rules.find(actor_name);
        if (ruleIt == rules.end()) throw config_err("Missing rule actor config for actor: " + actor_name);

        Actor_config &currentRuleReq = *ruleIt->second;

        for (size_t i = 0; i < options.size(); i++) {
            if (usedOptions.contains(i)) continue;
            if (!currentRuleReq.matches(*options[i])) continue;

            usedOptions.insert(i);
            currentAssignment.insert_or_assign(actor_name, options[i]);

            if (findSolution(ruleKeys, ruleIdx + 1, rules, options, usedOptions, currentAssignment)) return true;

            usedOptions.erase(i);
            currentAssignment.erase(actor_name);
        }
        return false;
    }

    ActorMap hw_capabilities::check_req_options(const ActorCMap &rules, const vector<ActorPtr> &options) {
        vector<string> ruleKeys;
        for (const auto &key : rules | views::keys) ruleKeys.push_back(key);

        ActorMap result;
        if (unordered_set<size_t> usedOptions; findSolution(ruleKeys, 0, rules, options, usedOptions, result)) {
            log(LogLevel::DEBUG, "Solved!");
            for (auto const &[r, o] : result) log(LogLevel::DEBUG, "\tRule "+r+" -> option "+ o->to_str());
            return result;
        }

        Actor_config::print_ActorCMap("Actor rules", rules);
        Actor_config::print_ActorCMap("Actor options", options);

        throw req_err("Not found valid requirements");
    }


    // RUN functions // TODO refactor

    void hw_capabilities::run_in(const string& cmd, const filesystem::path& cwd = filesystem::current_path()) {
        const string full_cmd = "cd " + cwd.string() + " && " + cmd;
        if (system(full_cmd.c_str()) != 0) {
            throw runtime_error("Command failed: " + cmd);
        }
    }

    int hw_capabilities::run_cmd(const vector<string> &argv, const optional<string> &netns) {
        if (argv.empty()) return -1;

        // prepend ip netns exec if netns is set
        vector<string> full_argv;
        if (netns.has_value()) {
            full_argv.reserve(argv.size() + 4);
            full_argv.emplace_back("ip");
            full_argv.emplace_back("netns");
            full_argv.emplace_back("exec");
            full_argv.push_back(*netns);
            full_argv.insert(full_argv.end(), argv.begin(), argv.end());
        } else {
            full_argv = argv;
        }

        vector<char *> args;
        args.reserve(full_argv.size() + 1);
        for (auto &s : full_argv) {args.push_back(const_cast<char *>(s.c_str()));}
        args.push_back(nullptr);

        const pid_t pid = fork();

        if (pid < 0) {log(LogLevel::ERROR, "fork() failed for command "+full_argv[0]); return -1;}
        if (pid == 0) {execvp(args[0], args.data());_exit(127);}

        int status = 0;
        if (waitpid(pid, &status, 0) < 0) {
            log(LogLevel::ERROR, "waitpid() failed for command "+ full_argv[0]);
            return -1;
        }

        if (WIFSIGNALED(status)) {
            log(LogLevel::WARNING, "Command %s terminated by signal %d", full_argv[0].c_str(), WTERMSIG(status));
        } else if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            log(LogLevel::ERROR, "Command %s exited with status %d", full_argv[0].c_str(), WEXITSTATUS(status));
        }
        return WEXITSTATUS(status);
    }

    int hw_capabilities::freq_to_channel(const int freq) {
        // 2.4 GHz
        if (freq == 2484) return 14;
        if (freq >= 2412 && freq <= 2472) {
            const int ch = (freq - 2407) / 5;
            if ((freq - 2407) % 5 == 0) return ch;
        }

        // 5 GHz
        if (freq >= 5180 && freq <= 5885) {
            const int ch = (freq - 5000) / 5;
            if ((freq - 5000) % 5 == 0) return ch;
        }

        // 6 GHz
        if (freq >= 5955 && freq <= 7115) {
            const int ch = (freq - 5950) / 5;
            if ((freq - 5950) % 5 == 0) return ch;
        }

        throw std::invalid_argument("Invalid frequency: " + std::to_string(freq) + " MHz");
    }

    int hw_capabilities::channel_to_freq(const int channel, const WifiBand band) {
        // 2.4 GHz
        if(band == WifiBand::BAND_2_4 || band == WifiBand::BAND_2_4_or_5){
            if (channel == 14) return 2484;
            if (channel >= 1 && channel <= 13) return 2407 + channel * 5;
        }
        // 5 GHz
        if(band == WifiBand::BAND_5 || band == WifiBand::BAND_2_4_or_5){
            if (channel >= 36 && channel <= 177) {
                if ((channel - 36) % 4 == 0 || channel == 177) return 5000 + channel * 5;
            }
        }

        // 6 GHz
        if(band == WifiBand::BAND_6){
            if (channel >= 1 && channel <= 233) {
                const int freq = 5950 + channel * 5;
                if (freq >= 5955 && freq <= 7115) return freq;
            }
        }
        throw std::invalid_argument("Invalid channel: " + std::to_string(channel));
    }
    string hw_capabilities::run_cmd_output(const vector<string> &argv) {
        if (argv.empty()) return {};

        vector<char *> args;
        args.reserve(argv.size() + 1);
        for (const auto &s : argv) { args.push_back(const_cast<char *>(s.c_str())); }
        args.push_back(nullptr);

        int pipefd[2];
        if (pipe(pipefd) < 0) return {};

        const pid_t pid = fork();
        if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return {}; }

        if (pid == 0) {
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd[1]);
            execvp(args[0], args.data());
            _exit(127);
        }

        close(pipefd[1]);
        string output;
        char buf[256];
        ssize_t n;
        while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {output.append(buf, static_cast<size_t>(n));}
        close(pipefd[0]);
        waitpid(pid, nullptr, 0);
        return output;
    }

    void hw_capabilities::create_ns(const string &ns_name){
        run_cmd({"sudo","ip", "netns", "add", ns_name});
        run_cmd({"sudo","ip", "netns", "exec", ns_name, "ip", "link", "set", "lo", "up"});
    }

    string hw_capabilities::rand_mac() {
        static random_device rd;
        static mt19937 gen(rd());
        uniform_int_distribution<> dis(0, 255);

        char mac[18];
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
            dis(gen), dis(gen), dis(gen), dis(gen), dis(gen), dis(gen));
        return string(mac);
    }

    string hw_capabilities::get_iface(const string& ip_address) {
        const string output = run_cmd_output({"ip", "route", "get", ip_address});
        if (output.empty()) throw runtime_error("Failed to get route for IP: "+ip_address);

        smatch match;
        if (!regex_search(output, match, regex(R"(dev (\S+))"))){throw runtime_error("Could not find interface for IP: "+ip_address);}

        return match[1].str();
    }
}
