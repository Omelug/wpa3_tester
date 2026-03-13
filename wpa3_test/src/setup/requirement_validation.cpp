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

using namespace std;
using nlohmann::json;
namespace wpa3_tester{

    void RunStatus::parse_requirements() {
        for (const auto& [actor_name, actor] : config.at("actors").items()) {
            auto [it, inserted] = actors.emplace(actor_name, ActorPtr(std::make_shared<Actor_config>(actor)));
            it->second->str_con["actor_name"] = actor_name;
        }
    }

    static vector<pid_t> pids_in_ns(const string& ns_name) {
        const string ns_path = "/var/run/netns/" + ns_name;

        struct stat ns_stat{};
        if (stat(ns_path.c_str(), &ns_stat) != 0) return {};
        const ino_t target_inode = ns_stat.st_ino;

        vector<pid_t> result;
        for (const auto& entry : filesystem::directory_iterator("/proc")) {
            const string filename = entry.path().filename().string();
            // only numeric entries (PIDs)
            if (filename.find_first_not_of("0123456789") != string::npos) continue;

            const string net_ns_link = entry.path().string() + "/ns/net";
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
            while (filesystem::exists("/proc/" + std::to_string(static_cast<long>(p)))) {
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
            {"sudo", "ip", "netns", "exec", ns_name, "ls", "/sys/class/net"});

        vector<string> result;
        istringstream ss(out);
        string iface;
        while (ss >> iface) {
            const int rc = hw_capabilities::run_cmd(
                {"sudo", "ip", "netns", "exec", ns_name, "test", "-e", "/sys/class/net/" + iface + "/device"},
                std::nullopt);
            if (rc == 0) {
                result.push_back(iface);
                log(LogLevel::DEBUG, "Physical iface in ns %s: %s", ns_name.c_str(), iface.c_str());
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
                if (!filesystem::exists("/sys/class/net/" + name)) {
                    all_present = false;
                    break;
                }
            }
            if (all_present) return;
            this_thread::sleep_for(chrono::milliseconds(20));
        }
        for (const auto& name : ifaces) {
            if (!filesystem::exists("/sys/class/net/" + name)) {
                log(LogLevel::WARNING, "Interface %s did not return to root ns in time!", name.c_str());
            }
        }
    }

    void cleanup_all_namespaces() {
        namespace fs = filesystem;
        log(LogLevel::INFO, "Global cleanup: returning interfaces and removing namespaces...");
        const fs::path netns_dir = "/var/run/netns";
        if (!fs::exists(netns_dir)) { log(LogLevel::INFO, "Cleanup complete."); return;}

        for (const auto& ns_entry : fs::directory_iterator(netns_dir)) {
            const string ns_name = ns_entry.path().filename().string();

            const vector<string> physical_interfaces = psy_if_in_ns(ns_name);
            kill_process_in_ns_name(ns_name);
            hw_capabilities::run_cmd({"sudo", "ip", "netns", "del", ns_name});
            wait_to_default_ns(physical_interfaces);

            log(LogLevel::DEBUG, "Removed netns %s", ns_name.c_str());
        }
        log(LogLevel::INFO, "Cleanup complete.");
    }

    ActorCMap get_actors(const ActorCMap& actors, const std::string& source) {
        std::unordered_map<std::string, ActorPtr> result;
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
        const ActorCMap options_internal = internal_options();

        //find interface mapping
        auto internal_actors = get_actors(actors, "internal");
        internal_mapping = hw_capabilities::check_req_options(internal_actors, options_internal);
        for (auto &[actor_name, actor] : internal_actors) {
            auto& opt_actor = options_internal.at(internal_mapping.at(actor_name));
            actor->setup_actor(config, opt_actor);
        }

        // ------------------ EXTERNAL WHITEBOX ----------------------
        const ActorCMap options_external = external_wb_options();
        auto external_wb_actors = get_actors(actors, "external");
        external_mapping = hw_capabilities::check_req_options(external_wb_actors, options_external);

        for (auto &[actor_name, actor] : external_wb_actors) {
            auto& opt_actor = options_external.at(external_mapping.at(actor_name));
            actor->setup_actor(config, opt_actor);
        }


        // ------------------ EXTERNAL BLACKBOX ---------------------------

        // ---------------- SIMULATIONS -------------------------
        // TODO: simulation -> check hw compatibility
        //ActorCMap options_simulation =  create_simulation();
        // check if possible with simulation
        // create simulation

    }
}