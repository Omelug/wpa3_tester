#pragma once
#include <memory>
#include <string>
#include <unordered_map>
#include <nlohmann/json.hpp>

#include "ActorPtr.h"
#include "Actor_config.h"
#include "ObserverPtr.h"
#include "observer/grapth/graph_elements.h"
#include "system/ProcessManager.h"

namespace wpa3_tester{
    enum CONFIG_TYPE{TEST,TEST_SUITE};
    inline auto var_PREFIX = std::string("var_");

    class Actor_config;
    class ExternalConn;
    class GraphElements;

    using ActorMap = std::unordered_map<std::string, ActorPtr>;
    using ObserverMap = std::unordered_map<std::string, observer::ObserverPtr>;

    std::string current_time_string();
    std::string relative_from(const std::string& base_dir_name, const std::string& config_path);

    class RunStatus {
        // in actors are all actors in test
        // internal have key string iface, external MAC

    public:
        //public only for testing
        ActorCMap actors{};
        ObserverMap observers{};

        bool only_stats = false;
        static inline const std::filesystem::path BASE_FOLDER = std::filesystem::current_path() / "data" / "wpa3_test";
        nlohmann::json config{};
        std::string run_folder{};
        std::string config_path{};

        ActorCMap internal_mapping{};
        ActorCMap external_wb_mapping{};
        ActorCMap external_bb_mapping{};
        //ActorCMap simulation_mapping;

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
        static std::vector<ActorPtr> list_external_entities(
            const std::string &iface, size_t timeout_sec, const std::vector<int> &channels
        );

        void log_events(std::vector<std::unique_ptr<GraphElements>>& elements,
            // { actor_name, pattern, label, color }
            std::initializer_list<std::tuple<std::string, std::string, std::string, std::string>> event_d) const;

    private:

        // to scan available interfaces
        static std::vector<ActorPtr> internal_options();
        static void add_actors_by_radio(std::vector<ActorPtr> & options, const ActorPtr & cfg);
        static std::vector<ActorPtr> external_wb_options();
        std::vector<int> get_external_BB_channels();
        std::vector<ActorPtr> external_bb_options();
        //static std::vector<ActorPtr> create_simulation();

    public:
        void parse_requirements();

        static nlohmann::json extends_recursive(const nlohmann::json &config_json, const std::string &config_path);
        static void validate_recursive(nlohmann::json &current_node, const std::filesystem::path &base_dir);
        static nlohmann::json config_validation(const std::string &config_path);
        static void ensure_requirement(const std::string &req);
        void check_local_requirements();
        void config_requirement();
        void setup_test();
        void run_test();
        void stats_test();
        void save_actor_interface_mapping() const;
    };

    inline RunStatus* globalRunStatus = nullptr;
}
