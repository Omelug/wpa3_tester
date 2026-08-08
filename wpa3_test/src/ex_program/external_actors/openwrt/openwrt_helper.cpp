#include "ex_program/external_actors/openwrt/openwrt_helper.h"
#include <fstream>
#include <optional>
#include "logger/log.h"

namespace wpa3_tester::openwrt{
using namespace std;
using namespace filesystem;

namespace{

struct AssociatedSta{
	Tins::HWAddress<6> mac;
	int auth_alg;
};

optional<AssociatedSta> parse_associated_sta_line(const string &line){
	const auto sta_pos = line.find("Add associated STA ");
	if(sta_pos == string::npos) return nullopt;

	const auto mac_start = sta_pos + string("Add associated STA ").size();
	const auto mac_end = line.find_first_of(" \t\n\r(", mac_start);
	const string mac_text = line.substr(mac_start, mac_end == string::npos ? string::npos : mac_end - mac_start);

	const auto alg_pos = line.find("auth_alg=", mac_end);
	if(alg_pos == string::npos) return nullopt;
	const auto alg_start = alg_pos + string("auth_alg=").size();
	const auto alg_end = line.find_first_of(" \t\n\r)", alg_start);
	const string alg_text = line.substr(alg_start, alg_end == string::npos ? string::npos : alg_end - alg_start);

	try{
		return AssociatedSta{Tins::HWAddress<6>(mac_text), stoi(alg_text)};
	} catch(...){
		return nullopt;
	}
}

//TODO přesunout do něčeho obecn-eho
// IEEE 802.11 Authentication Algorithm Number, as hostapd logs it
string auth_alg_name(const int code){
	switch(code){
		case 0: return "Open System";
		case 1: return "Shared Key";
		case 2: return "FT";
		case 3: return "SAE";
		case 4: return "FILS SK";
		case 5: return "FILS SK PFS";
		case 6: return "FILS PK";
		default: return "auth_alg:" + to_string(code);
	}
}
}

string akm_from_openwrt_log(const path &log_path, const Tins::HWAddress<6> &client_mac, const TimeWindow window){
	ifstream f(log_path);
	string line;
	const bool has_filter = client_mac != Tins::HWAddress<6>();

	while(get_line_before_window(f, line, window)){
		const auto sta = parse_associated_sta_line(line);
		if(!sta) continue;
		if(has_filter && sta->mac != client_mac) continue;

		const string name = auth_alg_name(sta->auth_alg);
		if(sta->auth_alg == 3) return name + "\n(WPA3)"; // SAE
		return name;
	}
	return {};
}

string mfp_from_openwrt_log(const path &log_path, const Tins::HWAddress<6> &client_mac, const TimeWindow window){
	ifstream f(log_path);
	string line;
	const bool has_filter = client_mac != Tins::HWAddress<6>();

	while(get_line_before_window(f, line, window)){
		const auto sta = parse_associated_sta_line(line);
		if(!sta) continue;
		if(has_filter && sta->mac != client_mac) continue;

		return sta->auth_alg == 3 ? "REQUIRED" : "";
	}
	return {};
}

}