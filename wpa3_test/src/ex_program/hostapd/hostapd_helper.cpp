#include "config/global_config.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::hostapd{
    using namespace std;
    using namespace filesystem;


    void ensure_repo_cloned(const path& hostapd_folder) {
        const path repo_path = hostapd_folder / "hostapd";
        if (exists(repo_path)) {return;}

        log(LogLevel::INFO, "Cloning hostapd repository into "+repo_path.string()+"...");

        error_code ec;
        create_directories(hostapd_folder, ec);
        if (ec) {throw runtime_error("Failed to create directory: "+hostapd_folder.string());}

        const string clone_cmd = "git clone https://w1.fi/hostap.git hostapd";
        hw_capabilities::run_in(clone_cmd, hostapd_folder);
        log(LogLevel::INFO, "Repository cloned successfully");
    }

    string find_matching_tag(const path& repo_dir, const string& version) {
        string version_normalized = version;
        ranges::replace(version_normalized, '.', '_');
        const string target_tag = "hostap_"+version_normalized;

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
                log(LogLevel::INFO, "Found tag match: "+t );
                return t;
            }
        }

        throw runtime_error("No hostapd tag found for version: "+version);
    }

    void build_version(const string& version, const path& build_folder, path target) {
        path repo_path = build_folder / "hostapd";
        path hostapd_dir = repo_path / "hostapd";
        string tag = "hostapd_"+version;
        ranges::replace(tag, '.', '_');

        path config_path = hostapd_dir / ".config";
        if (!exists(config_path)) {copy(hostapd_dir / "defconfig", config_path);}

        ofstream conf(config_path, ios::app);
        conf << "\n# --- Wi-Fi Framework Testing Extensions ---"
            "\nCONFIG_IEEE80211W=y"         //PMF
            "\nCONFIG_SAE=y"
            "\nCONFIG_WNM=y"                // Wireless Network Management (needed in BSS Transition)
            "\nCONFIG_OCV=y"                // Operating Channel Validation
            "\nCONFIG_IEEE80211N=y"         // 802.11n
            "\nCONFIG_IEEE80211AC=y"        // 802.11ac (VHT)
            "\nCONFIG_IEEE80211AX=y"        // 802.11ax (HE / Wi-Fi 6)
            "\nCONFIG_IEEE80211R=y"         // Fast BSS Transition (FT)
            "\nCONFIG_INTERWORKING=y"       // 802.11u / Hotspot 2.0
            "\nCONFIG_TESTING_OPTIONS=y"    // extra cli commands, injection
            "\nCONFIG_CTRL_IFACE=y"         // hostapd_cli
            "\nCONFIG_DEBUG_FILE=y"         // debug logging o file
            "\n";
        conf.close();

        log(LogLevel::INFO, "Compiling hostapd "+version+" ... ");
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

        const string hostapd_folder_str = get_global_config().at("paths").at("hostapd").at("hostapd_build_folder");
        const path hostapd_folder(hostapd_folder_str);

        string bin_name = "hostapd_"+version;
        ranges::replace(bin_name, '.', '_');
        const path hostapd_bin = hostapd_folder / bin_name;

        // return if exists
        if (exists(hostapd_bin)) {
            log(LogLevel::INFO, "Using existing hostapd binary: "+hostapd_bin.string());
            return hostapd_bin.string();
        }

        // preparation for build
        ensure_repo_cloned(hostapd_folder);
        const path repo_path = hostapd_folder / "hostapd";
        const string tag = find_matching_tag(repo_path, version);

        hw_capabilities::run_in("git fetch --tags", repo_path);
        hw_capabilities::run_in("git reset --hard HEAD", repo_path);
        hw_capabilities::run_in("git clean -fd", repo_path);

        hw_capabilities::run_in("git fetch --tags", repo_path);
        hw_capabilities::run_in("git checkout "+tag, repo_path);

        build_version(version, hostapd_folder, hostapd_bin);
        copy(repo_path / "hostapd" / "hostapd", hostapd_bin, copy_options::overwrite_existing);
        return hostapd_bin;
    }

    void build_wpa_supplicant_version(const string& version, const path& build_folder, path target) {
        path repo_path = build_folder / "hostapd";
        path wpa_supp_dir = repo_path / "wpa_supplicant";

        path config_path = wpa_supp_dir / ".config";
        if (!exists(config_path)) {
            copy(wpa_supp_dir / "defconfig", config_path);
        }

        ofstream conf(config_path, ios::app);
        conf << "\n# --- Configuration changes for the Wi-Fi Framework ---"
            "\nCONFIG_SAE=y"
            "\nCONFIG_TESTING_OPTIONS=y"
            "\nCONFIG_FRAMEWORK_EXTENSIONS=y"
            "\nCONFIG_IEEE80211W=y"         // PMF
            "\nCONFIG_WNM=y"                // Wireless Network Management
            "\nCONFIG_OCV=y"                // Operating Channel Validation
            "\nCONFIG_IEEE80211N=y"         // 802.11n
            "\nCONFIG_IEEE80211AC=y"        // 802.11ac (VHT)
            "\nCONFIG_IEEE80211AX=y"        // 802.11ax (HE / Wi-Fi 6)
            "\nCONFIG_IEEE80211R=y"         // Fast BSS Transition (FT)
            "\nCONFIG_INTERWORKING=y"       // 802.11u / Hotspot 2.0
            "\nCONFIG_CTRL_IFACE=y"         // wpa_cli
            "\nCONFIG_DEBUG_FILE=y"         // debug logging to file
            "\n";
        conf.close();

        log(LogLevel::INFO, "Compiling wpa_supplicant "+version+" ... ");
        hw_capabilities::run_in("make clean", wpa_supp_dir);
        hw_capabilities::run_in("make -j$(nproc)", wpa_supp_dir);

        copy_file(wpa_supp_dir / "wpa_supplicant", target, copy_options::overwrite_existing);
        permissions(target, perms::owner_all | perms::group_exec);
    }

    string get_wpa_supplicant(const string &version) {
        if (version.empty()) {
            log(LogLevel::WARNING, "wpa_supplicant version not defined, using system default");
            return "wpa_supplicant";
        }

        const string hostapd_folder_str = get_global_config().at("paths").at("hostapd").at("hostapd_build_folder");
        const path hostapd_folder(hostapd_folder_str);

        string bin_name = "wpa_supplicant_"+version;
        ranges::replace(bin_name, '.', '_');
        const path wpa_supp_bin = hostapd_folder / bin_name;

        // return if exists
        if (exists(wpa_supp_bin)) {
            log(LogLevel::INFO, "Using existing wpa_supplicant binary: "+wpa_supp_bin.string());
            return wpa_supp_bin.string();
        }

        // preparation for build
        ensure_repo_cloned(hostapd_folder);
        const path repo_path = hostapd_folder / "hostapd";
        const string tag = find_matching_tag(repo_path, version);
        hw_capabilities::run_in("git fetch --tags", repo_path);
        hw_capabilities::run_in("git checkout "+tag, repo_path);

        build_wpa_supplicant_version(version, hostapd_folder, wpa_supp_bin);
        copy(repo_path / "wpa_supplicant" / "wpa_supplicant", wpa_supp_bin, copy_options::overwrite_existing);
        return wpa_supp_bin;
    }
}
