#pragma once
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <nlohmann/json.hpp>

#include "ActorPtr.h"
#include "Actor_config.h"
#include "system/ProcessManager.h"

namespace wpa3_tester{

    enum CONFIG_TYPE{
        TEST,
        TEST_SUITE
    };

    struct ExternalEntity {
        std::string mac;
        std::string ssid;
        int channel = 0;
        int signal  = 0;
        bool is_ap  = false;
    };

    class Actor_config;
    class ExternalConn;
    using AssignmentMap = std::map<std::string,std::string>;

    class RunStatus {
        // in actors are all actors in test
        // internal have key string iface, external mac
        ActorCMap actors{};

    public:
        bool only_stats = false;
        static inline const std::filesystem::path BASE_FOLDER = std::filesystem::current_path() / "data" / "wpa3_test";
        nlohmann::json config{};
        std::string run_folder{};
        std::string config_path{};

        //mapping actor->interface
        AssignmentMap internal_mapping{};
        //mapping actor->MAC
        AssignmentMap external_mapping{};

        //AssignmentMap simulation_mapping;

        ProcessManager process_manager{};

        RunStatus() = default;
        explicit RunStatus(const std::string & config_path, std::string testName = "");
        void execute();
        static void solve_new_pdu(Tins::PDU &pdu, std::map<std::string, ExternalEntity> &seen);
        static std::unordered_map<std::string,std::string> scan_attack_configs(CONFIG_TYPE ct = TEST);

        ActorPtr &get_actor(const std::string &actor_name);
        static void get_or_create_connection(ActorPtr &actor);
        static void print_test_list();
        static std::string findConfigByTestName(const std::string &name);

        // For manual testing / wizards
        static std::vector<ExternalEntity> list_external_entities(const std::string& iface, int timeout_sec);


    private:

        // to scan available interfaces
        static ActorCMap internal_options();
        static ActorCMap external_wb_options();
        static ActorCMap external_bb_options();
        ActorCMap create_simulation();

        void parse_requirements();

    public:
        static nlohmann::json extends_recursive(const nlohmann::json &current_node, const std::string &config_path);
        static void validate_recursive(nlohmann::json &current_node, const std::filesystem::path &base_dir);
        static nlohmann::json config_validation(const std::string &config_path);
        void config_requirement();
        void setup_test();
        void run_test();
        void stats_test();
        void save_actor_interface_mapping() const;
    };

    inline RunStatus* globalRunStatus = nullptr;
}
