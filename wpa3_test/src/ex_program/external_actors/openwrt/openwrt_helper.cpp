#include "ex_program/external_actors/openwrt/openwrt_helper.h"
#include <fstream>
#include "logger/log.h"

namespace wpa3_tester::openwrt{
using namespace std;
using namespace filesystem;

string akm_from_openwrt_log(const path &log_path, const TimeWindow window){
	ifstream f(log_path);
	string line;
	const bool bounded = window.start_tp.time_since_epoch().count() != 0;
	while(getline(f, line)){
		if(bounded){ const auto tp = log_time_to_epoch_ns(line); if(tp.time_since_epoch().count() != 0 && tp >= window.start_tp) break; }
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

string mfp_from_openwrt_log(const path &log_path, const TimeWindow window){
	ifstream f(log_path);
	string line;
	const bool bounded = window.start_tp.time_since_epoch().count() != 0;
	while(getline(f, line)){
		if(bounded){ const auto tp = log_time_to_epoch_ns(line); if(tp.time_since_epoch().count() != 0 && tp >= window.start_tp) break; }
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
