#include "config/global_paths.h"
#include "setup/config_parser.h"
#include "logger/error_log.h"
#include <yaml-cpp/yaml.h>
#include <filesystem>

namespace wpa3_tester {
    using namespace std;
    using namespace filesystem;
    using json = nlohmann::json;

    nlohmann::json& get_global_config() {
        static json global_paths_cache{};
        static bool loaded = false;

        if (!loaded) {
            try {
                const path global_paths_file = path(PROJECT_ROOT_DIR) / "attack_config" / "global_config.yaml";
                if (!exists(global_paths_file)) {
                    throw config_error("Global paths configuration file not found: " + global_paths_file.string());
                }

                const YAML::Node yaml_node = YAML::LoadFile(global_paths_file.string());
                global_paths_cache = yaml_to_json(yaml_node);
                loaded = true;

            } catch (const YAML::Exception& e) {
                throw config_error(string("Failed to parse global_paths.yaml: ") + e.what());
            } catch (const exception& e) {
                throw config_error(string("Failed to load global_paths.yaml: ") + e.what());
            }
        }
        return global_paths_cache;
    }
}

