#include "ex_program/hostapd/hostapd_helper.h"
#include <fstream>
#include <regex>
#include <set>
#include <nlohmann/json.hpp>
#include "hostapd_cflags.h"
#include "config/global_config.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"
#include <byteswap.h>

namespace wpa3_tester::hostapd{
using namespace std;
using namespace filesystem;

struct RepoConfig{
	string repo_name;       // "hostapd", "hostapd-mana"
	string git_url;         // https://git.w1.fi/hostap.git, etc.
	string binary_name;     // "hostapd"/"hostapd-mana"
	bool has_tags;          // hostapd has tags, hostapd-mana uses pinned commit
	string tag_prefix;      // "hostap_" for hostapd
	string pinned_commit;   // if set, always checkout this commit (ignores version)
	string no_version_name; // "hostapd"/"hostapd-mana" installed
};

static const RepoConfig HOSTAPD_CONFIG = {
	"hostapd", "https://git.w1.fi/hostap.git", "hostapd", true, "hostap_", "", "hostapd",
};

// Kali master HEAD (2026-07-27)
static const RepoConfig HOSTAPD_MANA_CONFIG = {
	"hostapd_mana", "https://gitlab.com/kalilinux/packages/hostapd-mana.git", "hostapd",
	false, "hostapd-mana_", "490fc93b177f525bf8a479d122ded1844a68e510", "hostapd-mana"
};

void ensure_git_repo_cloned(const path &base_folder, const RepoConfig &cfg){
	const path repo_path = base_folder / cfg.repo_name;
	if(exists(repo_path)){ return; }

	log(LogLevel::INFO, "Cloning {} repository into {}...", cfg.repo_name, repo_path);

	error_code ec;
	create_public_dirs(base_folder, ec);
	if(ec){ throw run_err("Failed to create directory: {}", base_folder); }

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
		tag = trim(tag);
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

void build_hostapd_like(const string &version, const path &build_folder, const path &target, const RepoConfig &cfg,
						const optional<OpenSSLPaths> &openssl = nullopt
){
	path repo_path = build_folder / cfg.repo_name;
	path source_dir = repo_path / "hostapd";

	path config_path = source_dir / ".config";
	copy(source_dir / "defconfig", config_path, copy_options::overwrite_existing);

	ofstream conf(config_path, ios::app);
	conf << "\n# --- Wi-Fi Framework Testing Extensions ---" "\nCONFIG_LIBNL32=y"
			"\nCONFIG_IEEE80211W=y" "\nCONFIG_SAE=y" "\nCONFIG_WNM=y"
			"\nCONFIG_OCV=y" "\nCONFIG_OWE=y"
			"\nCONFIG_SUITEB192=y" "\nCONFIG_DPP=y" "\nCONFIG_IEEE80211N=y" "\nCONFIG_IEEE80211AC=y";
	if(cfg.has_tags) conf << "\nCONFIG_IEEE80211AX=y"; // mana beacon.c has broken AX call site
	if(cfg.repo_name == "hostapd_mana") conf << "\nCONFIG_MANA=y\nCONFIG_MANA_EAP=y\nCONFIG_SYCOPHANT=y";
	conf << "\nCONFIG_IEEE80211R=y" "\nCONFIG_INTERWORKING=y" "\nCONFIG_TESTING_OPTIONS=y"
			"\nCONFIG_CTRL_IFACE=y" "\nCONFIG_DEBUG_FILE=y" "\nCONFIG_EAP_PWD=y" "\n";
	conf.close();

	log(LogLevel::INFO, "Compiling {} {} ... ", cfg.repo_name, version);
	error_code rm_ec;
	remove_all(repo_path / "build", rm_ec); // may be root-owned from a previous privileged build
	hw_capabilities::run_in("make clean", source_dir);

	string extra = get_extra_cflags();
	if(cfg.repo_name == "hostapd_mana") extra += " -fcommon"; // mana defines globals in beacon.h
	string env_prefix;
	if(openssl){
		extra += " -I" + openssl->include_dir.string();
		// Set LDFLAGS env var so our -L precedes the system path injected by
		// `pkg-config --libs openssl` inside the hostapd Makefile. EXTRA_LDFLAGS
		// is appended too late and loses the search-order race against the system lib.
		env_prefix = "LDFLAGS=\"-L" + openssl->lib_dir.string() + "\" ";
	}
	hw_capabilities::run_in(env_prefix + "make EXTRA_CFLAGS=\"" + extra + "\" -j$(nproc)", source_dir);

	copy_f(source_dir / cfg.binary_name, target);
}

string get_binary(const string &bin_prefix, const string &version, const RepoConfig &cfg,
				const optional<OpenSSLPaths> &openssl = nullopt
){
	const string folder_key = (cfg.repo_name == "hostapd_mana") ? "hostapd_mana_build_folder" : "hostapd_build_folder";
	const string hostapd_folder_str = get_global_config().at("paths").at("hostapd").at(folder_key);
	const path hostapd_folder(hostapd_folder_str);

	if(version.empty() && cfg.pinned_commit.empty()){
		if(hw_capabilities::run_cmd({"which", cfg.no_version_name}, nullopt, false) != 0)
			throw config_err("{} version not set and '{}' not found in PATH", cfg.repo_name, cfg.no_version_name);
		log(LogLevel::WARNING, "{} version not defined, using system default", cfg.repo_name);
		return cfg.no_version_name;
	}

	// pinned repos always build the same commit — name binary by short hash, not version
	string bin_name = cfg.pinned_commit.empty()
		? bin_prefix + version
		: bin_prefix + cfg.pinned_commit.substr(0, 12);
	ranges::replace(bin_name, '.', '_');
	const path binary_path = hostapd_folder / bin_name;

	if(exists(binary_path)){
		log(LogLevel::INFO, "Using existing {} binary: {}", cfg.repo_name, binary_path);
		return binary_path;
	}

	ensure_git_repo_cloned(hostapd_folder, cfg);
	const path repo_path = hostapd_folder / cfg.repo_name;

	if(cfg.has_tags){
		const string tag = find_matching_tag(repo_path, version, cfg);
		try{ hw_capabilities::run_in("git fetch --tags", repo_path); } catch(const run_err &){
			log(LogLevel::WARNING, "git fetch --tags failed (offline?), using local tags");
		}
		hw_capabilities::run_in("git reset --hard HEAD", repo_path);
		hw_capabilities::run_in("git clean -fd", repo_path);
		hw_capabilities::run_in("git checkout " + tag, repo_path);
	} else{
		if(!cfg.pinned_commit.empty()){
			hw_capabilities::run_in("git fetch origin", repo_path);
		} else{
			try{ hw_capabilities::run_in("git fetch", repo_path); } catch(const run_err &){
				log(LogLevel::WARNING, "git fetch failed (offline?), using local version");
			}
		}
		hw_capabilities::run_in("git reset --hard HEAD", repo_path);
		hw_capabilities::run_in("git clean -fd", repo_path);
		if(!cfg.pinned_commit.empty()){
			hw_capabilities::run_in("git checkout " + cfg.pinned_commit, repo_path);
		}
	}

	build_hostapd_like(version, hostapd_folder, binary_path, cfg, openssl);
	copy(repo_path / "hostapd" / cfg.binary_name, binary_path, copy_options::overwrite_existing);
	return binary_path;
}

void build_wpa_supplicant_version(const string &version, const path &build_folder, const path &target){
	path repo_path = build_folder / "hostapd";
	path wpa_supp_dir = repo_path / "wpa_supplicant";

	path config_path = wpa_supp_dir / ".config";
	if(!exists(config_path)){
		copy(wpa_supp_dir / "defconfig", config_path);
	}

	ofstream conf(config_path, ios::app);
	conf << "\n# --- Configuration changes for the Wi-Fi Framework ---" "\nCONFIG_SAE=y" "\nCONFIG_TESTING_OPTIONS=y"
			"\nCONFIG_FRAMEWORK_EXTENSIONS=y" "\nCONFIG_IEEE80211W=y" "\nCONFIG_WNM=y" "\nCONFIG_OCV=y"
			"\nCONFIG_IEEE80211N=y" "\nCONFIG_IEEE80211AC=y" "\nCONFIG_IEEE80211AX=y" "\nCONFIG_IEEE80211R=y"
			"\nCONFIG_INTERWORKING=y" "\nCONFIG_CTRL_IFACE=y" "\nCONFIG_DEBUG_FILE=y" "\nCONFIG_EAP_PWD=y"
			"\nCONFIG_CTRL_IFACE_DBUS=" "\nCONFIG_CTRL_IFACE_DBUS_NEW=" "\nCONFIG_CTRL_IFACE_DBUS_INTRO=" "\n";
	conf.close();

	log(LogLevel::INFO, "Compiling wpa_supplicant {} ... ", version);
	hw_capabilities::run_in("make clean", wpa_supp_dir);
	const string extra = get_extra_cflags();
	hw_capabilities::run_in("make EXTRA_CFLAGS=\"" + extra + "\" -j$(nproc)", wpa_supp_dir);
	copy_f(wpa_supp_dir / "wpa_supplicant", target);
}

// --------- OPENSSL ---------

static const string OPENSSL_GIT_URL = "https://github.com/openssl/openssl.git";
static const string OPENSSL_REPO_NAME = "openssl";

static path get_openssl_build_folder(){
	return get_global_config().at("paths").at("openssl").at("openssl_vuln_build_folder").get<string>();
}

OpenSSLPaths get_openssl_paths(const string &tag){
	const path build_folder = get_openssl_build_folder();
	const path install_dir = build_folder / tag;
	const path lib_dir = install_dir / "lib";
	const path libcrypto = lib_dir / "libcrypto.so";
	const path include_dir = install_dir / "include";

	if(exists(libcrypto)){
		log(LogLevel::INFO, "Using existing OpenSSL {}: {}", tag, lib_dir);
		return {lib_dir, libcrypto, include_dir};
	}

	const path repo_path = build_folder / OPENSSL_REPO_NAME;
	if(!exists(repo_path)){
		log(LogLevel::INFO, "Cloning OpenSSL repository into {}...", repo_path);
		error_code ec;
		create_public_dirs(build_folder, ec);
		if(ec){ throw run_err("Failed to create directory: {}", build_folder); }
		hw_capabilities::run_in("git clone " + OPENSSL_GIT_URL + " " + OPENSSL_REPO_NAME, build_folder);
		log(LogLevel::INFO, "OpenSSL repository cloned successfully");
	}

	try{ hw_capabilities::run_in("git fetch --tags", repo_path); } catch(const run_err &){
		log(LogLevel::WARNING, "git fetch --tags failed (offline?), using local tags");
	}

	hw_capabilities::run_in("git reset --hard HEAD", repo_path);
	hw_capabilities::run_in("git clean -fd", repo_path);
	hw_capabilities::run_in("git checkout " + tag, repo_path);

	log(LogLevel::INFO, "Compiling OpenSSL {} ...", tag);
	const string prefix = install_dir.string();
	hw_capabilities::run_in("./config --prefix=" + prefix + " --openssldir=" + prefix + " shared no-asm", repo_path);
	hw_capabilities::run_in("make -j$(nproc)", repo_path);
	hw_capabilities::run_in("make install_sw", repo_path);

	if(!exists(libcrypto)){
		throw run_err("OpenSSL build succeeded but libcrypto.so not found at: {}", libcrypto);
	}
	log(LogLevel::INFO, "OpenSSL {} built and installed to {}", tag, install_dir);
	return {lib_dir, libcrypto, include_dir};
}

// --------- PUBLIC API ---------

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
		log(LogLevel::INFO, "Using existing wpa_supplicant binary: {}", wpa_supp_bin);
		return wpa_supp_bin.string();
	}

	ensure_git_repo_cloned(hostapd_folder, HOSTAPD_CONFIG);
	const path repo_path = hostapd_folder / "hostapd";
	const string tag = find_matching_tag(repo_path, version, HOSTAPD_CONFIG);
	try{ hw_capabilities::run_in("git fetch --tags", repo_path); } catch(const run_err &){
		log(LogLevel::WARNING, "git fetch --tags failed (offline?), using local tags");
	}
	hw_capabilities::run_in("git checkout " + tag, repo_path);

	build_wpa_supplicant_version(version, hostapd_folder, wpa_supp_bin);
	copy(repo_path / "wpa_supplicant" / "wpa_supplicant", wpa_supp_bin, copy_options::overwrite_existing);
	return wpa_supp_bin;
}

string get_hostapd(const string &version){
	return get_binary("hostapd_", version, HOSTAPD_CONFIG);
}

string get_hostapd_mana(const string &version){
	return get_binary("hostapd-mana_", version, HOSTAPD_MANA_CONFIG);
}

std::string to_hex(const uint8_t* data, size_t len) {
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (size_t i = 0; i < len; ++i) {
		ss << std::setw(2) << static_cast<int>(data[i]);
	}
	return ss.str();
}

CrackResult crack_pmk_hashes(const path &creds_file, const string &psk){
	if(hw_capabilities::run_cmd({"which", "hcxpmktool"}, nullopt, false) != 0)
		throw config_err("hcxpmktool not found in PATH - install hcxtools package");
	log(LogLevel::INFO, "hcxpmktool: {}", hw_capabilities::run_cmd_output({"hcxpmktool", "--version"}, nullopt));

	if(!exists(creds_file)){
		log(LogLevel::WARNING, "wpa.creds not found: {}", creds_file);
		return {0, 0};
	}

	ifstream f(creds_file);
	int total = 0, cracked = 0;
	string line;
	while(getline(f, line)){
		const auto tab_pos = line.find('\t');
		const string hash = (tab_pos != string::npos) ? line.substr(tab_pos + 1) : line;
		if(!hash.starts_with("WPA*")) continue;
		total++;
		if(hw_capabilities::run_cmd({"hcxpmktool", "-l", hash, "-p", psk}, nullopt, true) == 0)
			cracked++;
	}
	log(LogLevel::INFO, "hcxpmktool: {}/{} hashes cracked", cracked, total);
	return {total, cracked};
}


static path actor_conf_path(const RunStatus &rs, const string &actor_name){
	const auto &actor = rs.config().at("actors").at(actor_name);
	if(!actor.contains("setup")) return {};
	const string program = actor.at("setup").at("program").get<string>();
	return rs.run_folder() / (actor_name + (program == "wpa_supplicant" ? "_wpa_supplicant.conf" : "_hostapd.conf"));
}

string get_password(const RunStatus &rs, const string &actor_name){
	return get_conf_value(actor_conf_path(rs, actor_name), {"sae_password", "psk"});
}

string get_ssid(const RunStatus &rs, const string &actor_name){
	return get_conf_value(actor_conf_path(rs, actor_name), {"ssid"});
}

optional<bool> get_ocv(const RunStatus &rs, const string &actor_name){
	const auto v = get_conf_value(actor_conf_path(rs, actor_name), {"ocv"});
	if(v.empty()) return nullopt;
	return v == "1";
}

optional<bool> get_okc(const RunStatus &rs, const string &actor_name){
	const auto v = get_conf_value(actor_conf_path(rs, actor_name), {"okc"});
	return v == "1";
}

string get_version(const RunStatus &rs, const string &actor_name){
	const auto &a = rs.config().at("actors").at(actor_name);
	if(!a.contains("setup")) return "default";
	const auto &s = a.at("setup");
	if(!s.contains("program_config")) return "default";
	return s.at("program_config").value("version", "default");
}

string get_channel(const nlohmann::json &program_config, const string &config_path){
	if(program_config.contains("channel")) return to_string(program_config["channel"].get<int>());
	if(!config_path.empty()) if(const auto v = get_conf_value(config_path, {"channel"}); !v.empty()) return v;
	throw config_err("'channel' not found in program_config or file: {}", config_path);
}


string akm_from_ap_log(const path &log_path, const TimeWindow window){
    ifstream f(log_path);
    string line;
    string akm_fallback;
    const bool bounded = window.start_tp.time_since_epoch().count() != 0;

    while(getline(f, line)){
       if(bounded){
           const auto tp = log_time_to_epoch_ns(line);
           if(tp.time_since_epoch().count() != 0 && tp >= window.start_tp) break;
       }

       // 1. Explicitní textová AKM suita (pokud v logu je)
       const auto pos = line.find("AKM suite ");
       if(pos != string::npos){
          const auto start = pos + string("AKM suite ").size();
          const auto end = line.find_first_of(" \t\n\r]", start);
          string suite = line.substr(start, end == string::npos ? string::npos : end - start);
          if(suite.empty()) continue;
          if(suite.ends_with(":8")) return suite + "\n(WPA3)";
          if(suite.ends_with(":2")) return suite + "\n(WPA2)";
          return suite;
       }

       // 2. Detekce podle textového fallbacku (např. SAE / PSK)
       if(akm_fallback.empty()){
          const auto akm_pos = line.find("(AKM-defined - ");
          if(akm_pos != string::npos){
             const auto start = akm_pos + string("(AKM-defined - ").size();
             const auto end = line.find(')', start);
             if(end != string::npos) {
                 string val = line.substr(start, end - start);
                 if(val.find("SAE") != string::npos) return "00-0f-ac:8\n(WPA3)";
                 if(val.find("PSK") != string::npos) return "00-0f-ac:2\n(WPA2)";
             }
          }
       }

       // 3. Zpracování RSN IE, ale IGNORUJEME řádky s Beacon tail (abychom netahali globální nabídku AP)
       if(line.find("RSN IE in EAPOL-Key - hexdump") != string::npos) {
           // Hledáme specificky WPA3 (:8) nebo WPA2 (:2) uvnitř EAPOL-Key výměny
           if(line.find("00 0f ac 08") != string::npos) return "00-0f-ac:8\n(WPA3)";
           if(line.find("00 0f ac 02") != string::npos) return "00-0f-ac:2\n(WPA2)";
       }
    }
    return akm_fallback;
}

// RSN IE layout: tag(1) len(1) version(2) group_cipher(4)
//   pw_count(2) pw_suites(pw_count*4) akm_count(2) akm_suites(akm_count*4) rsn_caps(2) ...
struct RsnIe {
	vector<uint8_t> raw;
	uint16_t pw_count  = 0;
	size_t   akm_off   = 0; // offset of akm_count field
	uint16_t akm_count = 0;
	size_t   caps_off  = 0; // offset of rsn_caps field (2 bytes)
};

static optional<RsnIe> parse_rsn_ie_line(const string &line){
	const auto colon = line.rfind("): ");
	if(colon == string::npos) return nullopt;
	RsnIe ie;
	stringstream ss(line.substr(colon + 3));
	string tok;
	while(ss >> tok){
		try{ ie.raw.push_back(static_cast<uint8_t>(stoi(tok, nullptr, 16))); }
		catch(...){ break; }
	}
	if(ie.raw.size() < 10 || ie.raw[0] != 0x30) return nullopt;
	ie.pw_count = ie.raw[8] | (static_cast<uint16_t>(ie.raw[9]) << 8);
	ie.akm_off  = 10 + ie.pw_count * 4;
	if(ie.raw.size() < ie.akm_off + 2) return nullopt;
	ie.akm_count = ie.raw[ie.akm_off] | static_cast<uint16_t>(ie.raw[ie.akm_off + 1]) << 8;
	ie.caps_off  = ie.akm_off + 2 + ie.akm_count * 4;
	return ie;
}

static string akm_suite_name(uint8_t type){
	switch(type){
		case 1:  return "WPA-EAP";
		case 2:  return "WPA-PSK";
		case 3:  return "FT-EAP";
		case 4:  return "FT-PSK";
		case 6:  return "WPA-PSK-SHA256";
		case 8:  return "SAE";
		case 11: return "FT-SAE";
		case 18: return "OWE";
		default: return format("00-0f-ac:{}", type);
	}
}

//TODO test
string mfp_from_ap_log(const path &log_path, const TimeWindow window){
	ifstream f(log_path);
	string line;
	string mfp_fallback; // from older MFPC=/MFPR= log lines
	const bool bounded = window.start_tp.time_since_epoch().count() != 0;
	while(getline(f, line)){
		if(bounded){ const auto tp = log_time_to_epoch_ns(line); if(tp.time_since_epoch().count() != 0 && tp >= window.start_tp) break; }

		if(line.find("WPA: RSN IE in EAPOL-Key") != string::npos){
			const auto ie = parse_rsn_ie_line(line);
			if(!ie || ie->raw.size() < ie->caps_off + 2) continue;
			const uint16_t caps = ie->raw[ie->caps_off] | (static_cast<uint16_t>(ie->raw[ie->caps_off + 1]) << 8);
			if(!(caps & 0x0080)) return "OFF";            // MFPC
			return (caps & 0x0040) ? "REQUIRED" : "OPTIONAL"; // MFPR
		}

		if(mfp_fallback.empty()){
			const auto mfpc_pos = line.find("MFPC=");
			if(mfpc_pos != string::npos){
				const char mfpc = line.size() > mfpc_pos + 5 ? line[mfpc_pos + 5] : '0';
				if(mfpc != '1'){ mfp_fallback = "OFF"; continue; }
				const auto mfpr_pos = line.find("MFPR=");
				mfp_fallback = (mfpr_pos != string::npos && line.size() > mfpr_pos + 5 && line[mfpr_pos + 5] == '1')
					? "REQUIRED" : "OPTIONAL";
			}
		}
	}
	return mfp_fallback;
}
//TODO test
string client_akm_from_ap_log(const path &log_path, const TimeWindow window){
	ifstream f(log_path);
	string line;
	const bool bounded = window.start_tp.time_since_epoch().count() != 0;
	while(getline(f, line)){
		if(bounded){ const auto tp = log_time_to_epoch_ns(line); if(tp.time_since_epoch().count() != 0 && tp >= window.start_tp) break; }
		if(line.find("WPA: RSN IE in EAPOL-Key") == string::npos) continue;
		const auto ie = parse_rsn_ie_line(line);
		if(!ie || ie->akm_count == 0) continue;
		string result;
		for(uint16_t i = 0; i < ie->akm_count; ++i){
			const size_t suite_off = ie->akm_off + 2 + static_cast<size_t>(i * 4);
			if(ie->raw.size() < suite_off + 4) break;
			// only handle 00-0f-ac OUI
			if(ie->raw[suite_off] != 0x00 || ie->raw[suite_off+1] != 0x0f || ie->raw[suite_off+2] != 0xac) continue;
			if(!result.empty()) result += ' ';
			result += akm_suite_name(ie->raw[suite_off + 3]);
		}
		if(!result.empty()) return result;
	}
	return {};
}

//TODO test
string get_mfp_from_supplicant(const path &conf){
	if(!exists(conf)) return {};
	const string val = get_conf_value(conf, {"ieee80211w"});
	if(val == "1") return "OPTIONAL";
	if(val == "2") return "REQUIRED";
	if(val == "0") return "OFF";
	return {};
}

string owe_trans_bssid(const string &primary_mac){
	const auto addr = Tins::HWAddress<6>(primary_mac);
	return format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
				addr[0], addr[1], addr[2], addr[3], addr[4], addr[5] ^ 1);
}

//TODO test
string get_conf_value(const path &cfg, initializer_list<string_view> keys){
	ifstream f(cfg);
	string line;
	for(const string_view key: keys){
		f.clear();
		f.seekg(0);
		while(getline(f, line)){
			string s = line;
			s.erase(0, s.find_first_not_of(" \t"));
			if(!s.starts_with(string(key) + "=")) continue;
			string val = s.substr(key.size() + 1);
			if(val.size() >= 2 && val.front() == '"' && val.back() == '"') val = val.substr(1, val.size() - 2);
			return val;
		}
	}
	return {};
}


string get_hostapd_with_openssl(const string &hostapd_version, const string &openssl_version){
	const OpenSSLPaths ssl = get_openssl_paths(openssl_version);

	// binary name: hostapd_2_7_openssl_1_0_2e
	string openssl_suffix = openssl_version;
	ranges::replace(openssl_suffix, '-', '_');
	ranges::replace(openssl_suffix, '.', '_');

	const string folder_key = "hostapd_build_folder";
	const string hostapd_folder_str = get_global_config().at("paths").at("hostapd").at(folder_key);
	const path hostapd_folder(hostapd_folder_str);

	string bin_name = "hostapd_" + hostapd_version + "_" + openssl_suffix;
	ranges::replace(bin_name, '.', '_');
	const path binary_path = hostapd_folder / bin_name;

	if(exists(binary_path)){
		log(LogLevel::INFO, "Using existing hostapd+OpenSSL binary: {}", binary_path);
		return binary_path;
	}

	ensure_git_repo_cloned(hostapd_folder, HOSTAPD_CONFIG);
	const path repo_path = hostapd_folder / HOSTAPD_CONFIG.repo_name;

	const string tag = find_matching_tag(repo_path, hostapd_version, HOSTAPD_CONFIG);
	try{ hw_capabilities::run_in("git fetch --tags", repo_path); } catch(const run_err &){
		log(LogLevel::WARNING, "git fetch --tags failed (offline?), using local tags");
	}
	hw_capabilities::run_in("git reset --hard HEAD", repo_path);
	hw_capabilities::run_in("git clean -fd", repo_path);
	hw_capabilities::run_in("git checkout " + tag, repo_path);

	build_hostapd_like(hostapd_version, hostapd_folder, binary_path, HOSTAPD_CONFIG, ssl);
	copy(repo_path / "hostapd" / HOSTAPD_CONFIG.binary_name, binary_path, copy_options::overwrite_existing);
	return binary_path;
}

//TODO test
string client_scanning_from_ap_log(const path &ap_log, const string &client_mac){
	if(!exists(ap_log) || client_mac.empty()) return {};
	ifstream f(ap_log);
	string line;
	bool in_window = false;
	bool prev_was_probe = false;
	int prev_backup_ch = 0;
	set<int> channels;
	const regex freq_re(R"(freq=(\d+))");
	const regex ds_ch_re(R"(ds\.chan=(\d+))");
	smatch match;
	while(getline(f, line)){
		if(!in_window){
			if(line.contains(START_tag)) in_window = true;
			continue;
		}
		if(line.contains(END_tag) || line.contains(END_STOP_tag)) break;

		if(prev_was_probe){
			if(line.contains("DS Params mismatch") && regex_search(line, match, ds_ch_re))
				channels.insert(stoi(match[1].str()));
			else if(prev_backup_ch > 0)
				channels.insert(prev_backup_ch);
			prev_was_probe = false;
			prev_backup_ch = 0;
		}

		if(line.contains(client_mac) && line.contains("WLAN_FC_STYPE_PROBE_REQ")){
			prev_was_probe = true;
			if(regex_search(line, match, freq_re))
				prev_backup_ch = hw_capabilities::freq_to_channel(stoi(match[1].str()));
		}
	}
	if(prev_was_probe && prev_backup_ch > 0) channels.insert(prev_backup_ch);

	if(channels.empty()) return {};
	string result = "ch:";
	for(const int ch: channels) result += " " + to_string(ch);
	return result;
}
}
