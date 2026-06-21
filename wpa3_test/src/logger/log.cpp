#include "logger/log.h"
#include <iostream>
#include <memory>
#include <mutex>
#include <regex>
#include <vector>
#include "config/RunStatus.h"
#include "system/utils.h"

namespace wpa3_tester{
using namespace std;
using namespace chrono;
using namespace filesystem;

// Global state for log file
static mutex log_mutex;
static ofstream *log_file_ptr = nullptr;

const char *levelToString(const LogLevel level){
	switch(level){
	case LogLevel::DEBUG: return "DEBUG";
	case LogLevel::INFO: return "INFO";
	case LogLevel::WARNING: return "WARNING";
	case LogLevel::ERROR: return "ERROR";
	case LogLevel::CRITICAL: return "CRITICAL";
	}
	return "UNKNOWN";
}

void set_log_file(const path &log_path){
	lock_guard lock(log_mutex);
	if(log_file_ptr){
		log_file_ptr->close();
		delete log_file_ptr;
		log_file_ptr = nullptr;
	}

	if(!log_path.empty()){
		// Create parent directories if needed
		const path log_dir = log_path.parent_path();
		if(!log_dir.empty() && !exists(log_dir)){
			create_public_dirs(log_dir);
		}

		log_file_ptr = new ofstream(log_path, ios::app);
		if(!log_file_ptr->is_open()){
			delete log_file_ptr;
			log_file_ptr = nullptr;
		} else{
			set_public_perms(log_path);
		}
	}
}

void close_log_file(){
	lock_guard lock(log_mutex);
	if(log_file_ptr){
		log_file_ptr->close();
		delete log_file_ptr;
		log_file_ptr = nullptr;
	}
}

void write_log_message(const LogLevel level, const string &msg){
	const string formatted = string(levelToString(level)) + ": " + msg;

	// Write to stderr
	cerr << formatted << endl;

	// Write to log file if enabled
	{
		lock_guard lock(log_mutex);
		if(log_file_ptr && log_file_ptr->is_open()){
			*log_file_ptr << formatted << endl;
			log_file_ptr->flush();
		}
	}
}

void log(const LogLevel level, const string &msg){
	write_log_message(level, msg);
}

void log_actor_map(const string &name, const ActorCMap &m){
	auto keys_view = m | views::keys;
	const vector keys(keys_view.begin(), keys_view.end());
	const string keys_str = keys.empty() ? "<empty>" : join(keys, ", ");
	log(LogLevel::DEBUG, "{}:{}", name, keys_str);
}

// Returns a nanosecond-precision time_point (epoch == error sentinel)
LogTimePoint log_time_to_epoch_ns(const string &time_str){
	tm t = {};
	const char *p = strptime(time_str.c_str(), "%Y-%m-%dT%H:%M:%S", &t);
	if(p == nullptr) return LogTimePoint{};

	// parse fractional seconds ".310201504" → nanoseconds
	int64_t frac_ns = 0;
	if(*p == '.'){
		++p;
		int64_t scale = 100'000'000; // first digit = 100ms in ns
		while(isdigit(*p) && scale > 0){
			frac_ns += (*p - '0') * scale;
			scale /= 10;
			++p;
		}
		while(isdigit(*p)) ++p;
	}

	// parse timezone offset "+0100" / "-0500"
	int tz_offset_sec = 0;
	if(*p == '+' || *p == '-'){
		const int sign = (*p == '+') ? 1 : -1;
		++p;
		int hhmm = 0;
		for(int i = 0; i < 4 && isdigit(*p); ++i, ++p) hhmm = hhmm * 10 + (*p - '0');
		tz_offset_sec = sign * ((hhmm / 100) * 3600 + (hhmm % 100) * 60);
	}

	t.tm_isdst = 0;
	const time_t epoch_sec = timegm(&t) - tz_offset_sec;
	const auto total_ns = static_cast<int64_t>(epoch_sec) * 1'000'000'000LL + frac_ns;
	return LogTimePoint{nanoseconds{total_ns}};
}

vector<LogTimePoint> get_time_logs(const RunStatus &rs, const string &process_name, const string &pattern,
									bool between_markers
){
	vector<LogTimePoint> timestamps;
	const string actor_log = rs.run_folder() / "logger" / (process_name + ".log");
	if(!exists(actor_log)){
		log(LogLevel::ERROR, "Could not find file '{}'", actor_log);
		return {};
	}
	ifstream file(actor_log);
	string line;
	regex re(R"(^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{4}).*)" + pattern);
	smatch match;

	bool in_window = !between_markers;
	while(getline(file, line)){
		if(between_markers){
			if(line.find(START_tag) != string::npos){
				in_window = true;
				continue;
			}
			if(line.find(END_tag) != string::npos){
				in_window = false;
				continue;
			}
		}
		if(!in_window) continue;
		if(regex_search(line, match, re)){
			const LogTimePoint tp = log_time_to_epoch_ns(match[1].str());
			if(tp.time_since_epoch().count() != 0) timestamps.push_back(tp);
		}
	}
	return timestamps;
}

string escape_tex(string text){
	size_t pos = 0;
	while((pos = text.find('_', pos)) != string::npos){
		text.replace(pos, 1, "\\_");
		pos += 2;
	}
	return text;
}
}