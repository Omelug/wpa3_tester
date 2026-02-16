#include <yaml-cpp/node/node.h>
#include <yaml-cpp/node/parse.h>
#include "logger/error_log.h"
#include "logger/log.h"

namespace wpa3_tester::hostapd{
    using namespace std;
    using namespace filesystem;

    path get_build_folder() {
        /*path globalConfig = path(PROJECT_ROOT_DIR) /"attack_config"/"global_config.yaml";
        YAML::Node config = YAML::LoadFile(globalConfig.string());
        if (config["hostapd_build_folder"]) {
            return config["hostapd_build_folder"].as<string>();
        }
        //TODO invalid path ?
        throw std::runtime_error("hostapd_build_folder not found in global_config.yaml");*/
        throw not_implemented_error("neimplementováno");
    }

    string get_wpa_supplicant(nlohmann::json setup){
        /*if (!setup.contains("version") || setup["version"].is_null()) {
            log(LogLevel::WARNING, "No wpa_supplicant version specified, using system default.");
            return "wpa_supplicant";
        }

        string version = setup["version"].get<string>();
        string bin_name = "wpa_supplicant_" + version;
        ranges::replace(bin_name, '.', '_');
        path bin_path = get_build_folder() / bin_name;

        if (!exists(bin_path)) {
            log(LogLevel::INFO, ("Wpa_supplicant version " + version + " not found. Starting build...").c_str());
            build_version(version, get_build_folder());
        }

        return bin_path.string();*/
        throw not_implemented_error("neimplementováno");
    }

    string get_hostapd(nlohmann::json setup){
        //TODO
        /*if (!setup.contains("version") || setup["version"].is_null()) {
            log(LogLevel::WARNING, "No hostapd version specified, using system default.");
            return "hostapd";
        }
        string version = setup["version"].get<string>();
        string bin_name = "hostapd_" + version;
        replace(bin_name.begin(), bin_name.end(), '.', '_');
        fs::path bin_path = base_path / bin_name;

        // 2. Pokud binárka neexistuje, zkusíme ji sestavit
        if (!exists(bin_path)) {
            log(LogLevel::INFO, "Hostapd version " + version + " not found. Starting build...");
            try {
                HostapdManager::build_version(version, base_path);
            } catch (const exception& e) {
                log(LogLevel::ERROR, "Build failed: " + string(e.what()));
                log(LogLevel::WARNING, "Falling back to system default hostapd.");
                return "hostapd";
            }
        }

        return bin_path.string();*/
        throw not_implemented_error("neimplementováno");
    }

    void run(const string& cmd, const path& cwd = current_path()) {
        string full_cmd = "cd " + cwd.string() + " && " + cmd;
        if (system(full_cmd.c_str()) != 0) {
            throw runtime_error("Command failed: " + cmd);
        }
    }

    void build_version(const string& version, const path& build_folder) {
        path repo_path = build_folder / "hostapd";
        path hostapd_dir = repo_path / "hostapd";
        string tag = "hostapd_" + version;
        ranges::replace(tag, '.', '_');

        if (!exists(repo_path)) {
            run("git clone https://w1.fi/hostap.git hostapd", build_folder);
        }

        run("git fetch --tags", repo_path);
        run("git checkout " + tag, repo_path);

        path config_path = hostapd_dir / ".config";
        if (!exists(config_path)) {
            copy(hostapd_dir / "defconfig", config_path);
        }

        ofstream conf(config_path, ios::app);
        conf << "\nCONFIG_IEEE80211W=y"
                "\nCONFIG_SAE=y"
                "\nCONFIG_WNM=y"
                "\nCONFIG_OCV=y\n";
        conf.close();

        cout << "Compiling hostapd " << version << "..." << endl;
        run("make clean", hostapd_dir);
        run("make -j$(nproc)", hostapd_dir);

        path target = build_folder / ("hostapd_" + version);
        copy_file(hostapd_dir / "hostapd", target, copy_options::overwrite_existing);
        permissions(target, perms::owner_all | perms::group_exec);
    }
}
