#include "config/RunStatus.h"
#include "config/Actor_config.h"
#include "system/hw_capabilities.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include <chrono>
#include <filesystem>
#include <csignal>
#include <sstream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>

#include "config/Observer_config.h"

using namespace std;
using namespace filesystem;
using nlohmann::json;
namespace wpa3_tester{
    using namespace observer;
    void RunStatus::parse_requirements() {
        for (const auto& [actor_name, actor] : config.at("actors").items()) {
            auto [it, inserted] = actors.emplace(
                actor_name,
                ActorPtr(make_shared<Actor_config>(actor))
            );
            it->second->str_con["actor_name"] = actor_name;
        }
        if(!config.contains("observers")) return;
        for (const auto& [observer_name, observer] : config.at("observers").items()) {
            auto [it, inserted] = observers.emplace(
                observer_name,
                ObserverPtr(make_shared<Observer_config>(observer))
            );
            it->second->observer_name = observer_name;
        }
    }

    static vector<pid_t> pids_in_ns(const string& ns_name) {
        const string ns_path = "/var/run/netns/"+ns_name;

        struct stat ns_stat{};
        if (stat(ns_path.c_str(), &ns_stat) != 0) return {};
        const ino_t target_inode = ns_stat.st_ino;

        vector<pid_t> result;
        for (const auto& entry : filesystem::directory_iterator("/proc")) {
            const string filename = entry.path().filename().string();
            // only numeric entries (PIDs)
            if (filename.find_first_not_of("0123456789") != string::npos) continue;

            const string net_ns_link = entry.path().string()+"/ns/net";
            struct stat link_stat{};
            if (stat(net_ns_link.c_str(), &link_stat) != 0) continue;
            if (link_stat.st_ino == target_inode) {result.push_back(stoi(filename));}
        }
        return result;
    }

    void kill_process_in_ns_name(const string& ns_name){
        const vector<pid_t> pids = pids_in_ns(ns_name);
        if (pids.empty()) return;
        for (const pid_t p : pids) { kill(p, SIGTERM); }

        const auto deadline = chrono::steady_clock::now() + chrono::milliseconds(500);
        for (const pid_t p : pids) {
            while (filesystem::exists("/proc/"+to_string(static_cast<long>(p)))) {
                if (chrono::steady_clock::now() >= deadline) {
                    kill(p, SIGKILL);
                    break;
                }
                this_thread::sleep_for(chrono::milliseconds(10));
            }
            waitpid(p, nullptr, WNOHANG);
            log(LogLevel::DEBUG, "Killed process %d from namespace %s", p, ns_name.c_str());
        }
    }

    static vector<string> psy_if_in_ns(const string& ns_name) {
        const string out = hw_capabilities::run_cmd_output(
            {"ip", "netns", "exec", ns_name, "ls", "/sys/class/net"});

        vector<string> result;
        istringstream ss(out);
        string iface;
        while (ss >> iface) {
            const int rc = hw_capabilities::run_cmd(
                {"ip", "netns", "exec", ns_name, "test", "-e", "/sys/class/net/"+iface +"/device"},
                nullopt);
            if (rc == 0) {
                result.push_back(iface);
                log(LogLevel::DEBUG, "iface in ns "+ns_name+": "+iface);
            }
        }
        return result;
    }

    static void wait_to_default_ns(const vector<string>& ifaces,
    const chrono::milliseconds timeout = chrono::milliseconds(2000)) {
        if (ifaces.empty()) return;
        const auto start = chrono::steady_clock::now();
        while (chrono::steady_clock::now() - start < timeout) {
            bool all_present = true;
            for (const auto& name : ifaces) {
                if (!filesystem::exists("/sys/class/net/"+name)) {
                    all_present = false;
                    break;
                }
            }
            if (all_present) return;
            this_thread::sleep_for(chrono::milliseconds(20));
        }
        for (const auto& name : ifaces) {
            if (!filesystem::exists("/sys/class/net/"+name)) {
                log(LogLevel::WARNING, "Interface "+name+" did not return to root ns in time!");
            }
        }
    }

    void cleanup_all_namespaces() {
        log(LogLevel::INFO, "Global cleanup: returning interfaces and removing namespaces...");
        const path netns_dir = "/var/run/netns";
        if (!exists(netns_dir)) { log(LogLevel::INFO, "Cleanup complete."); return;}

        for (const auto& ns_entry : directory_iterator(netns_dir)) {
            const string ns_name = ns_entry.path().filename().string();

            const vector<string> physical_interfaces = psy_if_in_ns(ns_name);
            kill_process_in_ns_name(ns_name);
            hw_capabilities::run_cmd({"ip", "netns", "del", ns_name});
            wait_to_default_ns(physical_interfaces);

            log(LogLevel::DEBUG, "Removed netns "+ns_name);
        }
        log(LogLevel::INFO, "Cleanup complete.");
    }

    ActorCMap get_actors(const ActorCMap& actors, const string& source) {
        unordered_map<string, ActorPtr> result;
        for (auto& [name, cfg] : actors) {
            auto it = cfg->str_con.find("source");
            if (it != cfg->str_con.end() && it->second == source) {
                result.emplace(name, cfg);
            }
        }
        return result;
    }

    void RunStatus::config_requirement() {
        cleanup_all_namespaces();

        parse_requirements();
        log_actor_map("Actors: ", actors);

        // ------------------ INTERNAL ---------------------------
        auto internal_actors = get_actors(actors, "internal");
        if(!internal_actors.empty()){
            //find interface mapping
            internal_mapping = hw_capabilities::check_req_options(internal_actors, internal_options());
        }

        //  external wb/bb separation
        auto external_actors = get_actors(actors, "external");
        ActorCMap external_wb_actors;
        ActorCMap external_bb_actors;

        for (const auto &actor: external_actors | views::values){
           if(actor->is_external_WB()){
               external_wb_actors.emplace(actor["actor_name"], actor);
           }else{
               external_bb_actors.emplace(actor["actor_name"], actor);
           }
        }
        // ------------------ EXTERNAL WHITEBOX ----------------------
        if(!external_wb_actors.empty()){
            external_wb_mapping = hw_capabilities::check_req_options(external_wb_actors, external_wb_options());
        }

        // ------------------ EXTERNAL BLACKBOX ----------------------
        if (!external_bb_actors.empty()) {
            external_bb_mapping = hw_capabilities::check_req_options(external_bb_actors, external_bb_options());
        }

        // ---------------- SIMULATIONS -------------------------
        // simulation -> check hw compatibility
        //ActorCMap options_simulation =  create_simulation();
        // check if possible with simulation
        // create simulation

        // SETUP ACTORS
        for (auto &[actor_name, actor] : internal_actors) {
            auto& opt_actor = internal_mapping.at(actor_name);
            log(LogLevel::DEBUG, "Setup attempt for actor, current map size: %zu", actors.size());
            actor->setup_actor(config, opt_actor);
        }

        for (auto &[actor_name, actor] : external_wb_actors) {
            auto& opt_actor = external_wb_mapping.at(actor_name);
            actor->setup_actor(config, opt_actor);
        }

        for (auto &[actor_name, actor] : external_bb_actors) {
            auto& opt_actor = external_bb_mapping.at(actor_name);
            actor->setup_actor(config, opt_actor);
        }
    }
}