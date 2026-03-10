#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>
#include <sys/types.h>
#include <sys/wait.h>

#include "system/hw_capabilities.h"
#include "config/global_config.h"
#include "system/iface.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"

namespace wpa3_tester{
    using namespace std;

    string hw_capabilities::read_sysfs(const string &iface, const string &file){
        const string path = "/sys/class/net/" + iface + "/" + file;

        ifstream ifs(path);
        if(!ifs.is_open()){ throw config_error("Cant find %s", path.c_str());}

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
            throw config_error("Driver check error: %s", e.what());
        }
        throw config_error("Driver check error: not found valid symlink"); ;
    }

    int get_interface_arphrd_type(const filesystem::path& iface_path) {
        std::ifstream file(iface_path / "type");
        int type = 0;
        if (file >> type) return type;
        return 0;
    }

    vector<InterfaceInfo> hw_capabilities::list_interfaces(){
        std::vector<InterfaceInfo> result;
        const filesystem::path net_path = "/sys/class/net";

        if(!exists(net_path)) return result;
        for(const auto &entry: filesystem::directory_iterator(net_path)){
            std::string name = entry.path().filename().string();

            auto ignored_list = get_global_config().value("ignore_interfaces", std::vector<std::string>{});

            if(set ignored_set(ignored_list.begin(), ignored_list.end()); ignored_set.contains(name)){
                log(LogLevel::DEBUG, "Ignoring interface %s due to ignore_interfaces config", name.c_str());
                continue;
            }

            auto type = InterfaceType::Unknown;
            if(name == "lo"){
                type = InterfaceType::Loopback;  // Loopback ('lo')
            }else if(filesystem::exists(entry.path() / "wireless") || filesystem::exists(entry.path() / "phy80211")){
                if(name.rfind("mon", 0) == 0) { // start with mon //TODO  dirty but works ?
                    type = InterfaceType::WifiVirtualMon;  // Virtual wireless Wi-Fi (for monitor mode)
                }else{
                    type = InterfaceType::Wifi;   // wireless Wi-Fi
                }

            }else if(filesystem::exists(entry.path() / "bridge")){
                type = InterfaceType::DockerBridge;  // Docker Bridge ('bridge')
            }else if(filesystem::exists(entry.path() / "tun_flags")){
                type = InterfaceType::VPN; // VPN / TUN (tun_flags)
            } else if(name.find("veth") == 0){
                type = InterfaceType::VirtualVeth; // virtual veth docker container etc)
            } else if(filesystem::exists(entry.path() / "device")){
                type = InterfaceType::Ethernet; // Wire ethernet
            }
            result.push_back({name, type});
        }
        return result;
    }

    // ---------------------- BACKTRACKING ------------------------ Map of (RuleKey -> OptionKey)

    bool hw_capabilities::findSolution(
        const vector<string> &ruleKeys,
        const size_t ruleIdx,
        const ActorCMap &rules,
        const ActorCMap &options,
        set<string> &usedOptions,
        AssignmentMap &currentAssignment
    ){
        // all set? -> solution found
        if(ruleIdx == ruleKeys.size()){ return true; }

        const string &currentRuleKey = ruleKeys[ruleIdx];
        const auto &ruleIt = rules.find(currentRuleKey);
        if(ruleIt == rules.end() || !ruleIt->second){
            throw config_error("Missing rule actor config for key: %s", currentRuleKey.c_str());
        }
        Actor_config &currentRuleReq = *ruleIt->second;

        for(auto const &[optKey, optConfigPtr]: options){
            if(!optConfigPtr){ continue; } // skip empty
            if(usedOptions.contains(optKey)){ continue; } // already used this option

            if(Actor_config &optConfig = *optConfigPtr; !currentRuleReq.matches(optConfig)){ continue; } // node found

            usedOptions.insert(optKey);
            currentAssignment[currentRuleKey] = optKey;

            if(findSolution(ruleKeys, ruleIdx + 1, rules, options, usedOptions, currentAssignment)){
                return true; // found in subtree
            }

            usedOptions.erase(optKey);  // back in tree
            currentAssignment.erase(currentRuleKey);
        }
        return false; // no valid option for this rule
    }

    AssignmentMap hw_capabilities::check_req_options(const ActorCMap &rules, const ActorCMap &options){
        vector<string> ruleKeys;
        for(const auto &key: rules | views::keys) ruleKeys.push_back(key);
        AssignmentMap result;
        //backtracking
        if(set<string> usedOptions; findSolution(ruleKeys, 0, rules, options, usedOptions, result)){
            log(LogLevel::DEBUG, "Solved!");
            for(auto const &[r, o]: result){
                log(LogLevel::DEBUG, "\tActor %s -> interface %s", r.c_str(), o.c_str());
            }
            return result;
        }
        throw req_error("Not found valid requirements");
    }

    // RUN functions // TODO refactor

    void hw_capabilities::run_in(const string& cmd, const filesystem::path& cwd = filesystem::current_path()) {
        const string full_cmd = "cd " + cwd.string() + " && " + cmd;
        if (system(full_cmd.c_str()) != 0) {
            throw runtime_error("Command failed: " + cmd);
        }
    }

    int hw_capabilities::run_cmd(const vector<string> &argv, const std::optional<string> &netns) {
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
        if (pid < 0) {
            log(LogLevel::ERROR, "fork() failed for command %s", full_argv[0].c_str());
            return -1;
        }

        if (pid == 0) {execvp(args[0], args.data());_exit(127);}

        int status = 0;
        if (waitpid(pid, &status, 0) < 0) {
            log(LogLevel::ERROR, "waitpid() failed for command %s", full_argv[0].c_str());
            return -1;
        }

        if (WIFSIGNALED(status)) {
            log(LogLevel::WARNING,
                "Command %s terminated by signal %d",
                full_argv[0].c_str(), WTERMSIG(status));
        } else if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            log(LogLevel::ERROR,
                "Command %s exited with status %d",
                full_argv[0].c_str(), WEXITSTATUS(status));
        }
        return WEXITSTATUS(status);
    }

    int hw_capabilities::channel_to_freq_mhz(const int channel){
        // 2.4 GHz band: channels 1-13 -> 2412 + 5*(ch-1), channel 14 -> 2484
        if(channel >= 1 && channel <= 13){return 2412 + 5 * (channel - 1);}
        if(channel == 14){ return 2484;}

        // 5 GHz band common non-DFS channels mapping (extend as needed)
        switch(channel){
            case 36: return 5180;
            case 40: return 5200;
            case 44: return 5220;
            case 48: return 5240;
            case 52: return 5260;
            case 56: return 5280;
            case 60: return 5300;
            case 64: return 5320;
            case 100: return 5500;
            case 104: return 5520;
            case 108: return 5540;
            case 112: return 5560;
            case 116: return 5580;
            case 120: return 5600;
            case 124: return 5620;
            case 128: return 5640;
            case 132: return 5660;
            case 136: return 5680;
            case 140: return 5700;
            case 144: return 5720;
            case 149: return 5745;
            case 153: return 5765;
            case 157: return 5785;
            case 161: return 5805;
            case 165: return 5825;
            default:
                log(LogLevel::WARNING, "Unknown Wi-Fi channel %d, using 0 MHz", channel);
                return 0;
        }
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
        while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
            output.append(buf, static_cast<size_t>(n));
        }
        close(pipefd[0]);
        waitpid(pid, nullptr, 0);
        return output;
    }

    void hw_capabilities::create_ns(const std::string &ns_name){
        run_cmd({"sudo","ip", "netns", "add", ns_name});
        run_cmd({"sudo","ip", "netns", "exec", ns_name, "ip", "link", "set", "lo", "up"});
    }
}
