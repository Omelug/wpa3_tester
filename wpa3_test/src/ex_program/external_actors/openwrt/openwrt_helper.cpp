#include "ex_program/external_actors/openwrt/openwrt_helper.h"
#include <fstream>

namespace wpa3_tester::openwrt{
using namespace std;
using namespace filesystem;

string akm_from_openwrt_log(const path &log_path, const string &stop_tag){
	ifstream f(log_path);
	string line;
	while(getline(f, line)){
		if(line.find(stop_tag) != string::npos) break;
		if(line.find("AP-STA-CONNECTED") == string::npos) continue;
		const auto pos = line.find("auth_alg=");
		if(pos == string::npos) continue;
		const auto start = pos + string("auth_alg=").size();
		const auto end = line.find_first_of(" \t\n\r", start);
		const string alg = line.substr(start, end == string::npos ? string::npos : end - start);
		if(alg.find("sae") != string::npos) return alg + "\n(WPA3)";
		if(alg.find("psk") != string::npos) return alg + "\n(WPA2)";
		return alg;
	}
	return {};
}

string mfp_from_openwrt_log(const path &log_path, const string &stop_tag){
	ifstream f(log_path);
	string line;
	while(getline(f, line)){
		if(line.find(stop_tag) != string::npos) break;
		if(line.find("AP-STA-CONNECTED") == string::npos) continue;
		const auto pos = line.find("auth_alg=");
		if(pos == string::npos) continue;
		const auto start = pos + string("auth_alg=").size();
		const auto end = line.find_first_of(" \t\n\r", start);
		const string alg = line.substr(start, end == string::npos ? string::npos : end - start);
		if(alg.find("sae") != string::npos) return "REQUIRED";
		return {};
	}
	return {};
}

}
