#include "observer/trace_cmd_wrapper.h"
#include "config/RunStatus.h"
#include "logger/log.h"
#include "observer/observers.h"
#include "overview/described.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace wpa3_tester::observer::trace_cmd{
using namespace std;
using namespace filesystem;
using namespace chrono;

const string program_name = "trace_cmd";

const vector<pair<AmpduAction,string>>& ampdu_action_labels(){
	static const vector<pair<AmpduAction,string>> labels = {
		{AmpduAction::RX_START,           "RX_START"},
		{AmpduAction::RX_STOP,            "RX_STOP"},
		{AmpduAction::TX_OPERATIONAL,     "TX_OPERATIONAL"},
		{AmpduAction::TX_STOP_CONT,       "TX_STOP_CONT"},
		{AmpduAction::TX_STOP_FLUSH,      "TX_STOP_FLUSH"},
		{AmpduAction::TX_STOP_FLUSH_CONT, "TX_STOP_FLUSH_CONT"},
		{AmpduAction::TX_START,           "TX_START"},
		{AmpduAction::TX_START_DELAY,     "TX_START_DELAY"},
	};
	return labels;
}

void start_trace_cmd(RunStatus &rs, const string &actor_name, const vector<string> &events,
                     const vector<string> &kprobes){
	const path obs_folder = get_observer_folder(rs, program_name);
	const path dat_path   = obs_folder / (actor_name + "_trace.dat");
	const path txt_path   = obs_folder / (actor_name + "_trace.txt");
	const path ref_path   = obs_folder / (actor_name + "_trace_clock_ref.txt");

	// record wall/monotonic pair for monotonic->wall conversion in function what need time
	// Sampled together so the offset error is bounded by nanoseconds.
	{
		const auto mono = steady_clock::now();
		const auto wall = system_clock::now();
		ofstream ref(ref_path);
		ref << wall.time_since_epoch().count() << " " << mono.time_since_epoch().count() << "\n";
	}

	vector<string> command = {"trace-cmd", "record", "-o", dat_path.string()};
	for(const auto &e: events){ command.emplace_back("-e"); command.push_back(e); }
	for(const auto &k: kprobes){ command.emplace_back("--kprobe"); command.push_back(k); }

	rs.process_manager.run(actor_name + "_trace", command, obs_folder);
	rs.process_manager.after_stop(actor_name + "_trace", [dat_path, txt_path, ref_path](){
		// convert binary trace to human-readable; shell needed for stdout redirect
		hw_capabilities::run_cmd(
			{"sh", "-c", "trace-cmd report -i " + dat_path.string() + " > " + txt_path.string()}
		);
		if(exists(dat_path)) set_public_perms(dat_path);
		if(exists(txt_path)) set_public_perms(txt_path);
		if(exists(ref_path)) set_public_perms(ref_path);
	});
}

// "action:N" field - skips "drv_ampdu_action: " (space after colon, not digit)
static AmpduAction parse_action(const string &line){
	for(size_t p = 0; (p = line.find("action:", p)) != string::npos; p += 7){
		if(p + 7 < line.size() && isdigit(static_cast<unsigned char>(line[p + 7]))){
			try{
				const int v = stoi(line.substr(p + 7));
				if(v <= 7) return static_cast<AmpduAction>(v);
			} catch(...){}
			break;
		}
	}
	return AmpduAction::UNKNOWN;
}

// first digit-leading token ending with ':' is the monotonic timestamp; -1 on failure
// "SSSSSS.UUUUUU" - fractional part zero-padded to 9 digits for nanosecond precision
static int64_t line_ts_ns(const string &line){
	istringstream ss(line);
	for(string tok; ss >> tok; ){
		if(isdigit(static_cast<unsigned char>(tok.front())) && tok.back() == ':'){
			tok.pop_back();
			const auto dot = tok.find('.');
			if(dot == string::npos) return -1;
			try{
				string frac = tok.substr(dot + 1);
				frac.resize(9, '0');
				return stoll(tok.substr(0, dot)) * 1'000'000'000LL + stoll(frac);
			} catch(...){
				//FIXME at least log ?
				return -1;
			}
		}
	}
	return -1;
}

//TODO test
map<LogTimePoint, AmpduAction> get_bl0ck_logs(const RunStatus &rs,
											  const string &actor_name) {
	const path obs_folder = get_observer_folder(rs, program_name);
	const path txt_path = obs_folder / (actor_name + "_trace.txt");
	const path ref_path = obs_folder / (actor_name + "_trace_clock_ref.txt");

	if (!exists(txt_path)) {
		log(LogLevel::ERROR, "trace_cmd text not found: {}", txt_path.string());
		return {};
	}

	int64_t ref_wall_ns = 0, ref_mono_ns = 0;
	if (ifstream ref(ref_path); !(ref >> ref_wall_ns >> ref_mono_ns)) {
		log(LogLevel::WARNING, "trace_cmd clock ref missing: {}",
			ref_path.string());
		return {};
	}

	map<LogTimePoint, AmpduAction> result;
	ifstream file(txt_path);
	for (string line; getline(file, line);) {
		if (!line.contains("ampdu_action"))
			continue;
		const int64_t ts = line_ts_ns(line);
		if (ts < 0)
			continue;
		result[LogTimePoint{nanoseconds{ref_wall_ns + (ts - ref_mono_ns)}}] =
			parse_action(line);
	}
	return result;
}

//TODO test
described_bool addba_seen(const RunStatus &rs) {
	described_bool result;
	for (const string actor_name : {"ap", "client"}) {
		const auto opt = rs.actor(actor_name);
		if (!opt || !opt.value()->is_WB())
			continue;

		const path txt =
			get_observer_folder(rs, program_name) / (actor_name + "_trace.txt");
		if (!exists(txt))
			continue;

		bool found = false;
		ifstream f(txt);
		for (string line; getline(f, line) && !found;) {
			if (!line.contains("ampdu_action"))
				continue;
			const auto a = parse_action(line);
			found = (a == AmpduAction::RX_START || a == AmpduAction::TX_START);
		}
		result += {found, "trace_cmd " + actor_name};
	}
	return result;
}

}
