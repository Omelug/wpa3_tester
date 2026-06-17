#include <filesystem>
#include <fstream>
#include <iomanip>
#include <ios>
#include <iosfwd>
#include <random>
#include <string>
#include <vector>
#include <bits/ios_base.h>

#include "config/global_config.h"
#include "logger/error_log.h"
#include "system/hw_capabilities.h"

using namespace std;

namespace wpa3_tester::firmware{
string get_random_ath_masker_mac(const string &attacker_mac){
	stringstream ss(attacker_mac);
	string segment;
	vector<string> parts;

	while(getline(ss, segment, ':')){ parts.push_back(segment); }

	string result;
	for(int i = 0; i < 5; ++i){ result += parts[i] + ":"; }

	random_device rd;
	mt19937 gen(rd());
	uniform_int_distribution<> dis(0, 255);
	int random_byte = dis(gen);

	stringstream hex_ss;
	hex_ss << hex << setw(2) << setfill('0') << random_byte;
	result += hex_ss.str();
	return result;
}

void load_ath_masker(const bool git_install){
	const string ath_folder = get_global_config().at("paths").at("ath_masker");
	if(ath_folder.empty()) throw req_err("Setup paths/ath_masker in global_config:" + global_config_path().string());
	if(git_install){
		hw_capabilities::git_clone_or_pull("https://github.com/vanhoefm/ath_masker", ath_folder);
	} else if(!filesystem::exists(ath_folder)){
		throw req_err("ath_masker folder not found: " + ath_folder + ". Enable git_install or clone it manually.");
	}
	hw_capabilities::run_in("bash ./load.sh", ath_folder);
}

void unload_ath_masker(){
	const string ath_folder = get_global_config().at("paths").at("ath_masker");
	if(ath_folder.empty() || !filesystem::exists(ath_folder)) return;
	hw_capabilities::run_in("bash ./unload.sh", ath_folder);
}

void load_ath9k_noorder_change(){
	const string fw_dir = string(PROJECT_ROOT_DIR) + "/src/system/firmware/ath9k-firmware";
	hw_capabilities::run_in("bash ./install.sh", fw_dir);
}

void unload_ath9k_noorder_change(){
	const string fw_dir = string(PROJECT_ROOT_DIR) + "/src/system/firmware/ath9k-firmware";
	hw_capabilities::run_in("bash ./unload.sh", fw_dir);
}

bool is_ath_masker_loaded(){
	return filesystem::exists("/sys/module/ath_masker");
}

bool is_ath9k_noorder_loaded(){
	ifstream mounts("/proc/mounts");
	string line;
	while(getline(mounts, line)){
		if(line.find("ath9k_htc") != string::npos) return true;
	}
	return false;
}

void disable_custom_drivers(){
	if(is_ath_masker_loaded())    try{ unload_ath_masker(); } catch(...) {}
	if(is_ath9k_noorder_loaded()) try{ unload_ath9k_noorder_change(); } catch(...) {}
}
}