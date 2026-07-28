#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <nlohmann/json.hpp>
#include <tins/pdu.h>
#include "ObserverPtr.h"
#include "RunSuiteStatus.h"
#include "Run_Config.h"
#include "Actor_Config/ActorPtr.h"
#include "Actor_Config/Actor_config.h"
#include "observer/graph/graph_elements.h"
#include "system/ProcessManager.h"
#include "system/utils.h"

//hash for ActorMACMap
template<>
struct std::hash<Tins::HWAddress<6>>{
	size_t operator()(const Tins::HWAddress<6> &addr) const noexcept{
		size_t result = 0;
		for(const uint8_t byte: addr){
			result ^= std::hash<uint8_t>{}(byte) + 0x9e3779b9 + (result << 6) + (result >> 2);
		}
		return result;
	}
};

namespace wpa3_tester{
enum CONFIG_TYPE{ TEST, TEST_SUITE };

inline std::filesystem::path ATTACK_CONFIG(){ return root_dir() / "attack_config"; }
inline std::string var_PREFIX = "var_";

inline std::string START_tag = "@START";

//some function se only check for "@END" (can be prefix )
inline std::string END_tag = "@END";
inline std::string END_STOP_tag = "@END_STOP";

inline std::string ATTACK_START_tag ="@attack_start";
inline std::string ATTACK_STOP_tag ="@attack_stop";

class Actor_config;
class ExternalConn;
class GraphElements;

using ActorMap    = std::unordered_map<std::string, ActorPtr>;
using ActorMACMap = std::unordered_map<Tins::HWAddress<6>, ActorPtr>;
using AssocMap    = std::unordered_map<Tins::HWAddress<6>, Tins::HWAddress<6>>; // STA → AP BSSID
using EntityInfo  = std::pair<ActorPtr, std::pair<Tins::HWAddress<6>, Tins::HWAddress<6>>>; // (actor, (own_mac, peer_mac))
using ObserverMap = std::unordered_map<std::string, observer::ObserverPtr>;

//TODO nejde to nějak dát do struktury, ale aby vstup pro přehlcování unkcí zůstal stejný?
typedef std::string actor_name_t;
typedef std::string pattern_t;
typedef std::string label_t;
typedef std::string color_t;

enum EVENT_SET{
	DISCONNECT,
	CONNECT,
	TESTER_TAGS
};

class RunStatus{
	// in actors are all actors in test
	// internal have key string iface, external MAC
	static std::filesystem::path BASE_FOLDER(){ return root_dir().parent_path() / "data" / "wpa3_test"; }
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
	[[nodiscard]] const HwOptionCache &hw_option_cache() const{ return _hw_option_cache; }
	void hw_option_cache(const HwOptionCache &c){ _hw_option_cache = c; }
	[[nodiscard]] Run_Config run_config() const{ return _run_config; }
	void run_config(const Run_Config &rc){ _run_config.merge_from(rc); }
	//[[nodiscard]] nlohmann::json &config(){ return _config; }
	[[nodiscard]] const nlohmann::json &config() const{ return _config; }
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
	explicit RunStatus(const std::filesystem::path &config_path, std::string testName = "",
						const std::string &sub_folder = ""
	);
	void clean();
	void execute();
	static void solve_new_pdu(Tins::PDU &pdu, ActorMACMap &seen, AssocMap &assoc);
	static void solve_new_pdu(const std::vector<uint8_t> &pkt, ActorMACMap &seen, AssocMap &assoc);
	static bool should_skip(const std::filesystem::path &p);
	static std::unordered_map<std::string,std::string> scan_attack_configs(CONFIG_TYPE ct = TEST);

	std::optional<ActorPtr> actor(const std::string &actor_name);
	ActorPtr &get_actor(const std::string &actor_name);
	const ActorPtr &get_actor(const std::string &actor_name) const;
	static void get_or_create_connection(const ActorPtr &actor);
	static void print_test_list();
	void start_observers();
	static std::string findConfigByTestName(const std::string &name);

	// get external options
	// For manual testing / wizards
	static std::vector<EntityInfo> list_external_entities(const std::string &iface, size_t timeout_sec,
														const std::vector<unsigned char> &channels
	);
	// ----------- log_events
	// base
	void log_events(G_elms &elements,
		std::initializer_list<std::tuple<actor_name_t, pattern_t, label_t, color_t>> event_d
	) const;

	void log_events(G_elms &elements, const std::set<EVENT_SET> &event_sets) const;
private:
	static void add_actors_by_radio(std::vector<ActorPtr> &options, const ActorPtr &cfg);
	static std::vector<ActorPtr> external_wb_options();
protected:
	std::vector<uint8_t> get_external_BB_channels();
	std::vector<ActorPtr> external_bb_options(const ActorCMap &ex_bb_actors = {});
	static bool process_single_packet(const uint8_t *pkt, size_t len, ActorMACMap &seen, AssocMap &assoc,
									std::set<Tins::HWAddress<6>> &reported, const ActorCMap &actors,
									const std::vector<std::pair<std::string, std::string>> &conn_conds
	);
	static std::vector<ActorPtr> scan_until_match(const std::string &iface, const std::vector<uint8_t> &channels,
												const ActorCMap &actors,
												const std::vector<std::pair<std::string, std::string>> &conn_conds = {}
	);
public:
	static std::vector<ActorPtr> create_simulation(size_t n_radios);
	static std::vector<ActorPtr> internal_options();
	void parse_requirements();

	static nlohmann::json extends_recursive(const nlohmann::json &config_json, const std::filesystem::path &config_path
	);
	static void validate_recursive(nlohmann::json &current_node, const std::filesystem::path &base_dir);
	static nlohmann::json config_validation(const std::filesystem::path &config_path);
	void ensure_requirement(const std::string &req) const;
	void check_local_requirements();
	// use cache for options of actors

	//return true if re-reload
	bool config_requirement();
	void setup_test();
	void run_test();
	void stats_test() const;
	void save_actor_interface_mapping() const;
	void load_actor_interface_mapping();
	void save_result(const nlohmann::json &j) const;
	nlohmann::json load_result() const;
};

inline RunStatus *globalRunStatus = nullptr;
}
