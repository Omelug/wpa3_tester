#include <fstream>
#include "default.h"
#include "config/RunStatus.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/log_util.h"

namespace wpa3_tester::suite::helper{
using namespace std;
using namespace filesystem;
using json = nlohmann::json;

TimeWindow get_run_window(const RunStatus &rs){
	const path combined_log = rs.run_folder() / "logger" / "combined.log";
	if(!exists(combined_log)) return {};
	//first @END preferred
	return {get_tag_time(combined_log, START_tag), get_tag_time(combined_log, END_tag)};
}

optional<json> load_result_json(const path &test_folder){
	const auto result_json = test_folder / RESULT_NAME;
	if(!exists(result_json)) return nullopt;
	ifstream rf(result_json);
	return json::parse(rf);
}


// return (rogue_ap_connected, crack results)
pair<optional<bool>,optional<hostapd::CrackResult>> hostapd_mana_crack(const RunStatus &rs, vector<unique_ptr<GraphElements>> &elements){
	if(rs.config().at("actors").contains("rogue_ap")){
		const auto mana_events = get_time_logs(rs, "rogue_ap", "Captured a WPA");
		elements.push_back(make_unique<EventLines>(mana_events, "MANA", "black"));
		string psk = hostapd::get_password(rs, "client");
		if(psk.empty()) psk = "password123"; //TODO hardcoded, without warning log
		return {!mana_events.empty(),hostapd::crack_pmk_hashes(rs.run_folder()/"captured_hashes.txt", psk)};
	}
	return {nullopt, nullopt};
}


}
