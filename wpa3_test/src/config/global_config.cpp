#include "config/global_config.h"
#include "setup/config_parser.h"
#include "logger/error_log.h"
#include <yaml-cpp/yaml.h>
#include <filesystem>

namespace wpa3_tester {
    using namespace std;
    using namespace filesystem;
    using json = nlohmann::json;

    nlohmann::json& get_global_config() {
        static json global_config_cache{};
        static bool loaded = false;

        if (!loaded) {
            try {
                const path global_config_file = path(PROJECT_ROOT_DIR) / "attack_config" / "global_config.yaml";
                if (!exists(global_config_file)) {
                    throw config_err("Global paths configuration file not found: " + global_config_file.string());
                }

                const YAML::Node yaml_node = YAML::LoadFile(global_config_file.string());
                global_config_cache = yaml_to_json(yaml_node);
                loaded = true;

            } catch (const YAML::Exception& e) {
                throw config_err(string("Failed to parse global_config.yaml: ") + e.what());
            } catch (const exception& e) {
                throw config_err(string("Failed to load global_config.yaml: ") + e.what());
            }
        }
        return global_config_cache;
    }
}

