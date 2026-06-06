#include "ex_program/hostapd/hostapd_helper.h"
#include "hostapd_cflags.h"
#include "config/global_config.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"

namespace wpa3_tester::hostapd{
using namespace std;
using namespace filesystem;

struct RepoConfig {
	string repo_name;       // "hostapd", "hostapd-mana"
	string git_url;         // https://git.w1.fi/hostap.git, etc.
	string source_dir;      // "hostapd" for hostapd/hostapd-mana
	string binary_name;     // "hostapd"/"hostapd-mana"
	bool has_tags;          // hostapd has tags, hostapd-mana doesn't
	string tag_prefix;      // "hostap_" for hostapd
};

static const RepoConfig HOSTAPD_CONFIG = {
	"hostapd", "https://git.w1.fi/hostap.git", "hostapd", "hostapd", true, "hostap_"
};

static const RepoConfig HOSTAPD_MANA_CONFIG = {
	"hostapd-mana", "https://github.com/sensepost/hostapd-mana.git", "hostapd", "hostapd-mana", false, ""
};

void ensure_git_repo_cloned(const path &base_folder, const RepoConfig &cfg){
	const path repo_path = base_folder / cfg.repo_name;
	if(exists(repo_path)){ return; }

	log(LogLevel::INFO, "Cloning {} repository into {}...", cfg.repo_name, repo_path.string());

	error_code ec;
	create_public_dirs(base_folder, ec);
	if(ec){ throw run_err("Failed to create directory: " + base_folder.string()); }

	const string clone_cmd = "git clone " + cfg.git_url + " " + cfg.repo_name;
	hw_capabilities::run_in(clone_cmd, base_folder);
	log(LogLevel::INFO, "{} repository cloned successfully", cfg.repo_name);
}

string find_matching_tag(const path &repo_dir, const string &version, const RepoConfig &cfg){
	string version_normalized = version;
	ranges::replace(version_normalized, '.', '_');
	const string target_tag = cfg.tag_prefix + version_normalized;

	const string tags_output = hw_capabilities::run_cmd_output({"git", "-C", repo_dir.string(), "tag"});

	vector<string> tags;
	stringstream ss(tags_output);
	string tag;
	while(getline(ss, tag)){
		tag.erase(0, tag.find_first_not_of(" \t\r\n"));
		tag.erase(tag.find_last_not_of(" \t\r\n") + 1);
		if(!tag.empty()){ tags.push_back(tag); }
	}

	for(const auto &t: tags){
		if(t == target_tag){
			log(LogLevel::INFO, "Found tag match: {}", t);
			return t;
		}
	}

	throw run_err("No hostapd tag found for version: " + version);
}

static string get_extra_cflags(){
#ifdef HOSTAPD_EXTRA_CFLAGS
	return HOSTAPD_EXTRA_CFLAGS;
#else
	const char *v = getenv("EXTRA_CFLAGS");
	return v ? v : "";
#endif
}

void build_hostapd_like(const string &version, const path &build_folder, const path& target, const RepoConfig &cfg){
	path repo_path = build_folder / cfg.repo_name;
	path source_dir = repo_path / cfg.source_dir;

	path config_path = source_dir / ".config";
	if(!exists(config_path)){ copy(source_dir / "defconfig", config_path); }

	ofstream conf(config_path, ios::app);
	conf << "\n# --- Wi-Fi Framework Testing Extensions ---"
		"\nCONFIG_IEEE80211W=y"
		"\nCONFIG_SAE=y" "\nCONFIG_WNM=y"
		"\nCONFIG_OCV=y"
		"\nCONFIG_IEEE80211N=y"
		"\nCONFIG_IEEE80211AC=y"
		"\nCONFIG_IEEE80211AX=y"
		"\nCONFIG_IEEE80211R=y"
		"\nCONFIG_INTERWORKING=y"
		"\nCONFIG_TESTING_OPTIONS=y"
		"\nCONFIG_CTRL_IFACE=y"
		"\nCONFIG_DEBUG_FILE=y"
		"\nCONFIG_EAP_PWD=y" "\n";
	conf.close();

	log(LogLevel::INFO, "Compiling {} {} ... ", cfg.repo_name, version);
	hw_capabilities::run_in("make clean", source_dir);
	const string extra = get_extra_cflags();
	hw_capabilities::run_in("make EXTRA_CFLAGS=\"" + extra + "\" -j$(nproc)", source_dir);

	copy_f(source_dir / cfg.binary_name, target);
}

string get_binary(const string &bin_prefix, const string &version, const RepoConfig &cfg){
	const string folder_key = (cfg.repo_name == "hostapd-mana") ? "hostapd_mana_build_folder" : "hostapd_build_folder";
	const string hostapd_folder_str = get_global_config().at("paths").at("hostapd").at(folder_key);
	const path hostapd_folder(hostapd_folder_str);

	if(version.empty()){
		log(LogLevel::WARNING, "{} version not defined, using system default", cfg.repo_name);
		return cfg.binary_name;
	}

	string bin_name = bin_prefix + version;
	ranges::replace(bin_name, '.', '_');
	const path binary_path = hostapd_folder / bin_name;

	if(exists(binary_path)){
		log(LogLevel::INFO, "Using existing {} binary: {}", cfg.repo_name, binary_path.string());
		return binary_path.string();
	}

	ensure_git_repo_cloned(hostapd_folder, cfg);
	const path repo_path = hostapd_folder / cfg.repo_name;

	if(cfg.has_tags){
		const string tag = find_matching_tag(repo_path, version, cfg);
		try { hw_capabilities::run_in("git fetch --tags", repo_path); }
		catch(const run_err &){ log(LogLevel::WARNING, "git fetch --tags failed (offline?), using local tags"); }
		hw_capabilities::run_in("git reset --hard HEAD", repo_path);
		hw_capabilities::run_in("git clean -fd", repo_path);
		hw_capabilities::run_in("git checkout " + tag, repo_path);
	} else {
		try { hw_capabilities::run_in("git fetch", repo_path); }
		catch(const run_err &){ log(LogLevel::WARNING, "git fetch failed (offline?), using local version"); }
		hw_capabilities::run_in("git reset --hard HEAD", repo_path);
		hw_capabilities::run_in("git clean -fd", repo_path);
	}

	build_hostapd_like(version, hostapd_folder, binary_path, cfg);
	copy(repo_path / cfg.source_dir / cfg.binary_name, binary_path, copy_options::overwrite_existing);
	return binary_path.string();
}

void build_wpa_supplicant_version(const string &version, const path &build_folder, const path& target){
	path repo_path = build_folder / "hostapd";
	path wpa_supp_dir = repo_path / "wpa_supplicant";

	path config_path = wpa_supp_dir / ".config";
	if(!exists(config_path)){
		copy(wpa_supp_dir / "defconfig", config_path);
	}

	ofstream conf(config_path, ios::app);
	conf << "\n# --- Configuration changes for the Wi-Fi Framework ---"
		"\nCONFIG_SAE=y" "\nCONFIG_TESTING_OPTIONS=y"
		"\nCONFIG_FRAMEWORK_EXTENSIONS=y" "\nCONFIG_IEEE80211W=y"
		"\nCONFIG_WNM=y"
		"\nCONFIG_OCV=y"
		"\nCONFIG_IEEE80211N=y"
		"\nCONFIG_IEEE80211AC=y"
		"\nCONFIG_IEEE80211AX=y"
		"\nCONFIG_IEEE80211R=y"
		"\nCONFIG_INTERWORKING=y"
		"\nCONFIG_CTRL_IFACE=y"
		"\nCONFIG_DEBUG_FILE=y"
		"\nCONFIG_EAP_PWD=y"
		"\nCONFIG_CTRL_IFACE_DBUS="
		"\nCONFIG_CTRL_IFACE_DBUS_NEW="
		"\nCONFIG_CTRL_IFACE_DBUS_INTRO=" "\n";
	conf.close();

	log(LogLevel::INFO, "Compiling wpa_supplicant {} ... ", version);
	hw_capabilities::run_in("make clean", wpa_supp_dir);
	const string extra = get_extra_cflags();
	hw_capabilities::run_in("make EXTRA_CFLAGS=\"" + extra + "\" -j$(nproc)", wpa_supp_dir);
	copy_f(wpa_supp_dir / "wpa_supplicant", target);
	}

// --------- PUBLIC API ---------

CrackResult crack_pmk_hashes(const path &creds_file, const string &psk){
    if(!exists(creds_file)){
        log(LogLevel::WARNING, "wpa.creds not found: {}", creds_file.string());
        return {0, 0};
    }

    ifstream f(creds_file);
    int total = 0, cracked = 0;
    string line;
    while(getline(f, line)){
        // Lines are either "WPA*02*..." or "[WPA2-EAPOL HASHCAT]\tWPA*02*..."
        const auto tab_pos = line.find('\t');
        const string hash = (tab_pos != string::npos) ? line.substr(tab_pos + 1) : line;
        if(!hash.starts_with("WPA*")) continue;
        total++;
        // hcxpmktool exit 0 = confirmed, 2 = unconfirmed, 1 = error
        if(hw_capabilities::run_cmd({"hcxpmktool", "-l", hash, "-p", psk}, nullopt, false) == 0)
            cracked++;
    }
    log(LogLevel::INFO, "hcxpmktool: {}/{} hashes cracked", cracked, total);
    return {total, cracked};
}

string get_hostapd(const string &version){
	return get_binary("hostapd_", version, HOSTAPD_CONFIG);
}

string get_hostapd_mana(const string &version){
	return get_binary("hostapd-mana_", version, HOSTAPD_MANA_CONFIG);
}

string get_wpa_supplicant(const string &version){
	if(version.empty()){
		log(LogLevel::WARNING, "wpa_supplicant version not defined, using system default");
		return "wpa_supplicant";
	}

	const string hostapd_folder_str = get_global_config().at("paths").at("hostapd").at("hostapd_build_folder");
	const path hostapd_folder(hostapd_folder_str);

	string bin_name = "wpa_supplicant_" + version;
	ranges::replace(bin_name, '.', '_');
	const path wpa_supp_bin = hostapd_folder / bin_name;

	if(exists(wpa_supp_bin)){
		log(LogLevel::INFO, "Using existing wpa_supplicant binary: {}", wpa_supp_bin.string());
		return wpa_supp_bin.string();
	}

	ensure_git_repo_cloned(hostapd_folder, HOSTAPD_CONFIG);
	const path repo_path = hostapd_folder / "hostapd";
	const string tag = find_matching_tag(repo_path, version, HOSTAPD_CONFIG);
	try { hw_capabilities::run_in("git fetch --tags", repo_path); }
	catch(const run_err &){ log(LogLevel::WARNING, "git fetch --tags failed (offline?), using local tags"); }
	hw_capabilities::run_in("git checkout " + tag, repo_path);

	build_wpa_supplicant_version(version, hostapd_folder, wpa_supp_bin);
	copy(repo_path / "wpa_supplicant" / "wpa_supplicant", wpa_supp_bin, copy_options::overwrite_existing);
	return wpa_supp_bin;
}
}
