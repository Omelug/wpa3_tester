#include "config/global_paths.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::hostapd{
    using namespace std;
    using namespace filesystem;

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

    void ensure_repo_cloned(const path& hostapd_folder) {
        const path repo_path = hostapd_folder / "hostapd";
        if (exists(repo_path)) {return;}

        log(LogLevel::INFO, ("Cloning hostapd repository into " + repo_path.string() + "...").c_str());

        error_code ec;
        create_directories(hostapd_folder, ec);
        if (ec) {throw runtime_error("Failed to create directory: " + hostapd_folder.string());}

        const string clone_cmd = "git clone https://w1.fi/hostap.git hostapd";
        hw_capabilities::run_in(clone_cmd, hostapd_folder);
        log(LogLevel::INFO, "Repository cloned successfully");
    }

    string find_matching_tag(const path& repo_dir, const string& version) {
        string version_normalized = version;
        ranges::replace(version_normalized, '.', '_');
        const string target_tag = "hostapd_" + version_normalized;

        // Parse tags into vector
        const string tags_output = hw_capabilities::run_cmd_output({
            "git",
            "-C",
            repo_dir.string(),
            "tag"
        });

        vector<string> tags;
        stringstream ss(tags_output);
        string tag;
        while (getline(ss, tag)) {
            tag.erase(0, tag.find_first_not_of(" \t\r\n"));
            tag.erase(tag.find_last_not_of(" \t\r\n") + 1);
            if (!tag.empty()) {tags.push_back(tag);}
        }

        for (const auto& t : tags) {
            if (t == target_tag) {
                log(LogLevel::INFO, ("Found tag match: " + t).c_str());
                return t;
            }
        }

        throw runtime_error("No hostapd tag found for version: " + version);
    }

    void build_version(const string& version, const path& build_folder, path target) {
        path repo_path = build_folder / "hostapd";
        path hostapd_dir = repo_path / "hostapd";
        string tag = "hostapd_" + version;
        ranges::replace(tag, '.', '_');

        path config_path = hostapd_dir / ".config";
        if (!exists(config_path)) {copy(hostapd_dir / "defconfig", config_path);}

        ofstream conf(config_path, ios::app);
        conf << "\nCONFIG_IEEE80211W=y"
                "\nCONFIG_SAE=y"
                "\nCONFIG_WNM=y"
                "\nCONFIG_OCV=y\n";
        conf.close();

        log(LogLevel::INFO, "Compiling hostapd %s ... ", version.c_str());
        hw_capabilities::run_in("make clean", hostapd_dir);
        hw_capabilities::run_in("make -j$(nproc)", hostapd_dir);

        copy_file(hostapd_dir / "hostapd", target, copy_options::overwrite_existing);
        permissions(target, perms::owner_all | perms::group_exec);
    }

    string get_hostapd(const string &version) {
        if (version.empty()) {
            log(LogLevel::WARNING, "hostapd version not defined, using system default");
            return "hostapd";
        }

        const string hostapd_folder_str = get_global_paths().at("paths").at("hostapd").at("hostapd_build_folder");
        const path hostapd_folder(hostapd_folder_str);

        string bin_name = "hostapd_" + version;
        ranges::replace(bin_name, '.', '_');
        const path hostapd_bin = hostapd_folder / bin_name;

        // return if exists
        if (exists(hostapd_bin)) {
            log(LogLevel::INFO, ("Using existing hostapd binary: " + hostapd_bin.string()).c_str());
            return hostapd_bin.string();
        }

        // preparation for build
        ensure_repo_cloned(hostapd_folder);
        const path repo_path = hostapd_folder / "hostapd";
        const string tag = find_matching_tag(repo_path, version);
        hw_capabilities::run_in("git fetch --tags", repo_path);
        hw_capabilities::run_in("git checkout " + tag, repo_path);

        build_version(version, hostapd_folder, hostapd_bin);
        return hostapd_bin;
    }

}
