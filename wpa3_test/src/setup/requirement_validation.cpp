#include "config/RunStatus.h"
#include "config/Actor_config.h"
#include "system/hw_capabilities.h"
#include "logger/log.h"
#include <chrono>
#include <filesystem>
#include <csignal>
#include <sstream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <sys/mount.h>
#include "config/Observer_config.h"
#include "logger/error_log.h"
#include "attacks/two_iface/TwoIfaceActive.h"
#include "attacks/two_iface/TwoIfaceInject.h"

using namespace std;
using namespace filesystem;
using nlohmann::json;

namespace wpa3_tester{
using namespace observer;

void RunStatus::parse_requirements(){
	for(const auto &[actor_name, actor]: _config.at("actors").items()){
		auto [it, inserted] = actors.emplace(actor_name, ActorPtr(make_shared<Actor_config>(actor)));
		it->second->set(SK::actor_name, actor_name);
	}
	if(!_config.contains("observers")) return;
	for(const auto &[observer_name, observer]: _config.at("observers").items()){
		auto [it, inserted] = observers.emplace(observer_name, ObserverPtr(make_shared<Observer_config>(observer)));
		it->second->observer_name = observer_name;
	}
}

static vector<pid_t> pids_in_ns(const string &ns_name){
	const string ns_path = "/var/run/netns/" + ns_name;

	struct stat ns_stat{};
	if(stat(ns_path.c_str(), &ns_stat) != 0) return {};
	const ino_t target_inode = ns_stat.st_ino;

	vector<pid_t> result;
	for(const auto &entry: directory_iterator("/proc")){
		const string filename = entry.path().filename().string();
		// only numeric entries (PIDs)
		if(filename.find_first_not_of("0123456789") != string::npos) continue;

		const string net_ns_link = entry.path().string() + "/ns/net";
		struct stat link_stat{};
		if(stat(net_ns_link.c_str(), &link_stat) != 0) continue;
		if(link_stat.st_ino == target_inode){ result.push_back(stoi(filename)); }
	}
	return result;
}

void kill_process_in_ns_name(const string &ns_name){
	const vector<pid_t> pids = pids_in_ns(ns_name);
	if(pids.empty()) return;

	for(const pid_t p : pids) kill(p, SIGTERM);

	const auto deadline = chrono::steady_clock::now() + chrono::milliseconds(500);

	// Wait for all pids together under one shared deadline
	bool all_dead = false;
	while(!all_dead && chrono::steady_clock::now() < deadline){
		all_dead = true;
		for(const pid_t p : pids){
			if(exists("/proc/" + to_string(static_cast<long>(p))))
				all_dead = false;
		}
		if(!all_dead) this_thread::sleep_for(chrono::milliseconds(10));
	}

	// SIGKILL survivors
	for(const pid_t p : pids){
		if(exists("/proc/" + to_string(static_cast<long>(p)))){
			kill(p, SIGKILL);
			log(LogLevel::DEBUG, "SIGKILL process {} from namespace {}", p, ns_name);
		}
	}

	// Wait for SIGKILL to take effect — kernel needs a moment
	for(const pid_t p : pids){
		const auto kill_deadline = chrono::steady_clock::now() + chrono::milliseconds(200);
		while(exists("/proc/" + to_string(static_cast<long>(p))) &&
			  chrono::steady_clock::now() < kill_deadline)
			this_thread::sleep_for(chrono::milliseconds(5));

		waitpid(p, nullptr, WNOHANG);
		log(LogLevel::DEBUG, "Killed process {} from namespace {}", p, ns_name);
	}
}

static vector<string> psy_if_in_ns(const string &ns_name){
	const string out = hw_capabilities::run_cmd_output({"iw", "dev"}, ns_name);

	vector<string> result;
	istringstream ss(out);
	string token;
	while(ss >> token){
		if(token == "Interface"){
			string iface;
			if(ss >> iface){
				result.push_back(iface);
				log(LogLevel::DEBUG, "iface in ns {}:{}", ns_name, iface);
			}
		}
	}
	return result;
}

void delete_ns_and_wait(const string &ns_name, const vector<string> &ifaces,
	const chrono::milliseconds timeout = chrono::milliseconds(3000)){
	const string ns_path = "/var/run/netns/" + ns_name;

    // Open and bind netlink socket BEFORE touching the ns — umount2 alone can
    // drop the last reference and immediately return interfaces to root ns,
    // firing RTM_NEWLINK before we'd have a chance to subscribe.
    const int nl_fd = ifaces.empty() ? -1 :
        socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
    if(!ifaces.empty()){
        if(nl_fd < 0){
            log(LogLevel::WARNING, "netlink socket failed: {}", strerror(errno));
        } else {
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

    // Track which interfaces are still missing from root ns
    unordered_set waiting(ifaces.begin(), ifaces.end());
    // Remove ones already back
    for(auto it = waiting.begin(); it != waiting.end();)
        exists("/sys/class/net/" + *it) ? it = waiting.erase(it) : ++it;

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
            NLMSG_OK(nh, static_cast<uint32_t>(len));
            nh = NLMSG_NEXT(nh, len)){

            if(nh->nlmsg_type != RTM_NEWLINK) continue;

            const auto *ifi = static_cast<ifinfomsg *>(NLMSG_DATA(nh));
            int attr_len = nh->nlmsg_len - NLMSG_SPACE(sizeof(*ifi));
            auto *attr = reinterpret_cast<rtattr *>(
                static_cast<char *>(NLMSG_DATA(nh)) + NLMSG_ALIGN(sizeof(*ifi)));

            while(RTA_OK(attr, attr_len)){
                if(attr->rta_type == IFLA_IFNAME){
                    const string name = static_cast<char *>(RTA_DATA(attr));
                    if(waiting.contains(name) && exists("/sys/class/net/" + name)){
                        log(LogLevel::DEBUG, "Interface {} returned to root ns", name);
                        waiting.erase(name);
                    }
                }
                attr = RTA_NEXT(attr, attr_len);
            }
        }
    }
	close(nl_fd);
    for(const auto &name : waiting)
        log(LogLevel::WARNING, "Interface {} did not return to root ns in time", name);
}

void cleanup_all_namespaces(){
    log(LogLevel::INFO, "Global cleanup: performing scorched earth recovery...");

    // Remove mac80211_hwsim simulation interfaces first (no-op if not loaded)
    hw_capabilities::run_cmd({"modprobe", "-r", "mac80211_hwsim"}, nullopt, false);

    const path netns_dir = "/var/run/netns";
    if(!exists(netns_dir)){
        log(LogLevel::INFO, "Cleanup complete.");
        return;
    }

    for(const auto &entry : directory_iterator(netns_dir)){
        const auto ns_name = entry.path().filename().string();
        log(LogLevel::INFO, "Cleaning up processes in namespace: {}", ns_name);
        kill_process_in_ns_name(ns_name);

        const auto ifaces = psy_if_in_ns(ns_name);
        delete_ns_and_wait(ns_name, ifaces);
    }
    log(LogLevel::INFO, "Cleanup complete.");
}

ActorCMap get_actors(const ActorCMap &actors, const string &source){
	unordered_map<string,ActorPtr> result;
	for(auto &[name, cfg]: actors){
		auto it = cfg[SK::source];
		if(cfg[SK::source].has_value() && cfg[SK::source].value() == source){
			result.emplace(name, cfg);
		}
	}
	return result;
}

bool RunStatus::config_requirement(){
	check_local_requirements();
	cleanup_all_namespaces();
	parse_requirements();
	log_actor_map("Actors: ", actors);

	// ------------------ INTERNAL ---------------------------
	auto internal_actors = get_actors(actors, "internal");
	if(!internal_actors.empty()){
		if(!_hw_option_cache.internal_opts.has_value())
			_hw_option_cache.internal_opts = internal_options();
		internal_mapping = hw_capabilities::check_req_options(internal_actors, *_hw_option_cache.internal_opts);
	}

	//  external wb/bb separation
	auto external_actors = get_actors(actors, "external");
	ActorCMap external_wb_actors;
	ActorCMap external_bb_actors;

	for(const auto &actor: external_actors | views::values){
		if(actor->is_external_WB()){
			external_wb_actors.emplace(actor["actor_name"], actor);
		} else{
			external_bb_actors.emplace(actor["actor_name"], actor);
		}
	}
	// ------------------ EXTERNAL WHITEBOX ----------------------
	if(!external_wb_actors.empty()){
		if(!_hw_option_cache.external_wb_opts.has_value())
			_hw_option_cache.external_wb_opts = external_wb_options();
		external_wb_mapping = hw_capabilities::check_req_options(external_wb_actors, *_hw_option_cache.external_wb_opts);
	}

	// ------------------ EXTERNAL BLACKBOX ----------------------
	if(!external_bb_actors.empty()){
		external_bb_mapping = hw_capabilities::check_req_options(external_bb_actors, external_bb_options());
	}

	// ---------------- SIMULATIONS -------------------------
	auto simulation_actors = get_actors(actors, "simulation");
	if(!simulation_actors.empty()){
		const auto simulation_options = create_simulation(simulation_actors.size());
		simulation_mapping = hw_capabilities::check_req_options(simulation_actors, simulation_options);
	}

	// SETUP ACTORS
	for(auto &[actor_name, actor]: internal_actors){
		auto &opt_actor = internal_mapping.at(actor_name);
		log(LogLevel::DEBUG, "Setup attempt for actor, current map size: {}", actors.size());
		actor->setup_actor(_config, opt_actor);
	}

	//TODO simplify
	for(auto &[actor_name, actor]: external_wb_actors){
		auto &opt_actor = external_wb_mapping.at(actor_name);
		actor->setup_actor(_config, opt_actor);
	}

	for(auto &[actor_name, actor]: external_bb_actors){
		auto &opt_actor = external_bb_mapping.at(actor_name);
		actor->setup_actor(_config, opt_actor);
	}

	for(auto &[actor_name, actor]: simulation_actors){
		auto &opt_actor = simulation_mapping.at(actor_name);
		actor->setup_actor(_config, opt_actor);
	}
	// --------------- POST-BACKTRACKING REQUIREMENTS
	if(_config.contains("requirements") && _config.at("requirements").contains("two_iface")){
		for(const auto &[key, actor_names]: _config.at("requirements").at("two_iface").items()){
			if(!actor_names.is_array() || actor_names.size() < 2)
				throw config_err("two_iface." + key + " must be an array of two actor names");

			const ActorPtr &actor1 = get_actor(actor_names[0].get<string>());
			const ActorPtr &actor2 = get_actor(actor_names[1].get<string>());

			if(key == "active"){
				if(TwoIfaceActive::run_check(actor1, actor2, run_on_miss)) return true;
			} else if(key.starts_with("injection")){ //TODO inject_only separated tests
				if(TwoIfaceInject::run_check(actor1, actor2, run_on_miss, key)) return true;
			} else{
				throw not_implemented_err("two_iface test key not found: " + key);
			}
		}
	}
	return false;
}
}