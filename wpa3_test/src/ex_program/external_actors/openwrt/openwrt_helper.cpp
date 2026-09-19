#include "ex_program/external_actors/openwrt/openwrt_helper.h"
#include "logger/log.h"
#include <fstream>
#include <optional>

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

string uci_get_option(const path &uci_file, string_view block_type, string_view block_name, string_view key) {
	ifstream f(uci_file);
	string line;
	bool in_block = false;
	while (getline(f, line)) {
		const auto start = line.find_first_not_of(" \t");
		if (start == string::npos) continue;
		string_view sv(line.data() + start, line.size() - start);
		if (sv.starts_with("config ")) {
			sv.remove_prefix(7);
			const auto sp = sv.find(' ');
			const string_view type = sp == string_view::npos ? sv : sv.substr(0, sp);
			string_view name;
			if (sp != string_view::npos) {
				const auto q1 = sv.find('\'', sp);
				const auto q2 = q1 != string_view::npos ? sv.find('\'', q1 + 1) : string_view::npos;
				if (q1 != string_view::npos && q2 != string_view::npos)
					name = sv.substr(q1 + 1, q2 - q1 - 1);
			}
			in_block = (type == block_type && name == block_name);
		} else if (in_block && sv.starts_with("option ")) {
			sv.remove_prefix(7);
			const auto sp = sv.find(' ');
			if (sp == string_view::npos || sv.substr(0, sp) != key) continue;
			const auto rest = sv.substr(sp + 1);
			if (rest.starts_with('\'')) {
				const auto q2 = rest.find('\'', 1);
				if (q2 != string_view::npos) return string(rest.substr(1, q2 - 1));
			} else {
				return string(rest.substr(0, rest.find_first_of(" \t\r\n")));
			}
		}
	}
	return {};
}

string uci_get_option(const path &uci_file, string_view block_type,
		string_view filter_key, string_view filter_val, string_view key) {
	ifstream f(uci_file);
	string line;
	bool in_block = false;
	bool filter_matched = false;
	string pending;        // value of `key` seen before the filter matched

	auto parse_val = [](const string_view rest) -> string {
		if (rest.starts_with('\'')) {
			const auto q2 = rest.find('\'', 1);
			if (q2 != string_view::npos) return string(rest.substr(1, q2 - 1));
		}
		return string(rest.substr(0, rest.find_first_of(" \t\r\n")));
	};

	auto reset = [&](const bool enter) {
		in_block = enter; filter_matched = false; pending.clear();
	};

	while (getline(f, line)) {
		const auto start = line.find_first_not_of(" \t");
		if (start == string::npos) continue;
		string_view sv(line.data() + start, line.size() - start);
		if (sv.starts_with("config ")) {
			sv.remove_prefix(7);
			const auto sp = sv.find(' ');
			reset((sp == string_view::npos ? sv : sv.substr(0, sp)) == block_type);
		} else if (in_block && sv.starts_with("option ")) {
			sv.remove_prefix(7);
			const auto sp = sv.find(' ');
			if (sp == string_view::npos) continue;
			const auto opt_key = sv.substr(0, sp);
			const auto val     = parse_val(sv.substr(sp + 1));
			if (opt_key == filter_key && val == filter_val) {
				filter_matched = true;
				if (!pending.empty()) return pending;
			} else if (opt_key == key) {
				if (filter_matched) return val;
				pending = val;
			}
		}
	}
	return {};
}

string  akm_from_openwrt_log(const path &log_path, const Tins::HWAddress<6> &client_mac, const TimeWindow window){
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