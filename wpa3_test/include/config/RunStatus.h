#pragma once
#include <memory>
#include <string>
#include <unordered_map>
#include <nlohmann/json.hpp>

#include "ActorPtr.h"
#include "Actor_config.h"
#include "ObserverPtr.h"
#include "RunSuiteStatus.h"
#include "Run_Config.h"
#include "observer/graph/graph_elements.h"
#include "system/ProcessManager.h"

namespace wpa3_tester{
enum CONFIG_TYPE{ TEST, TEST_SUITE };

inline auto var_PREFIX = std::string("var_");

class Actor_config;
class ExternalConn;
class GraphElements;

using ActorMap = std::unordered_map<std::string,ActorPtr>;
using ObserverMap = std::unordered_map<std::string,observer::ObserverPtr>;

class RunStatus{
	// in actors are all actors in test
	// internal have key string iface, external MAC

	static inline const std::filesystem::path BASE_FOLDER = std::filesystem::current_path() / "data" / "wpa3_test";

protected:
	nlohmann::json _config{};
	std::filesystem::path _run_folder{};
	std::filesystem::path _config_path{};
	Run_Config _run_config{};
	ActorCMap internal_mapping{};
	ActorCMap external_wb_mapping{};
	ActorCMap external_bb_mapping{};
	ActorCMap simulation_mapping{};
	HwOptionCache _hw_option_cache{};
public:
	[[nodiscard]] const HwOptionCache& hw_option_cache() const { return _hw_option_cache; }
	void hw_option_cache(const HwOptionCache &c){ _hw_option_cache = c; }
	[[nodiscard]] Run_Config run_config() const{ return _run_config; }
	void run_config(const Run_Config &rc){ _run_config.merge_from(rc); }
	[[nodiscard]] nlohmann::json& config() { return _config;}
	[[nodiscard]] const nlohmann::json& config() const { return _config;}
	void config(const nlohmann::json &new_config){ this->_config = new_config; }
	[[nodiscard]] std::filesystem::path run_folder() const{ return _run_folder; }
	void run_folder(const std::filesystem::path &new_run_folder){ this->_run_folder = new_run_folder; }
	[[nodiscard]] std::filesystem::path config_path() const{ return _config_path; }
	void config_path(const std::filesystem::path &new_config_path){ this->_config_path = new_config_path; }

	//bool only_stats = false;
	//public only for testing
	ActorCMap actors{};
	ObserverMap observers{};
	ProcessManager process_manager{};

	RunStatus() = default;
	explicit RunStatus(const std::string &config_path, std::string testName = "", const std::string &sub_folder = "");
	void clean();
	void execute();
	static void solve_new_pdu(Tins::PDU &pdu, ActorMap &seen);
	static std::unordered_map<std::string,std::string> scan_attack_configs(CONFIG_TYPE ct = TEST);

	ActorPtr &get_actor(const std::string &actor_name);
	static void get_or_create_connection(const ActorPtr &actor);
	static void print_test_list();
	void start_observers();
	static std::string findConfigByTestName(const std::string &name);

	// For manual testing / wizards
	static std::vector<ActorPtr> list_external_entities(const std::string &iface, size_t timeout_sec,
														const std::vector<int> &channels
	);

	void log_events(std::vector<std::unique_ptr<GraphElements>> &elements,
					// { actor_name, pattern, label, color }
					std::initializer_list<std::tuple<std::string,std::string,std::string,std::string>> event_d
	) const;
private:
	// to scan available interfaces
	static std::vector<ActorPtr> internal_options();
	static void add_actors_by_radio(std::vector<ActorPtr> &options, const ActorPtr &cfg);
	static std::vector<ActorPtr> external_wb_options();
	std::vector<int> get_external_BB_channels();
	std::vector<ActorPtr> external_bb_options();
	static std::vector<ActorPtr> create_simulation(size_t n_radios);

public:
	void parse_requirements();

	static nlohmann::json extends_recursive(const nlohmann::json &config_json, const std::filesystem::path &config_path);
	static void validate_recursive(nlohmann::json &current_node, const std::filesystem::path &base_dir);
	static nlohmann::json config_validation(const std::filesystem::path &config_path);
	void ensure_requirement(const std::string &req) const;
	void check_local_requirements();
	// use cache for options of actors
	void config_requirement();
	void setup_test();
	void run_test();
	void stats_test() const;
	void save_actor_interface_mapping() const;
	void load_actor_interface_mapping();
};

inline RunStatus *globalRunStatus = nullptr;
}
