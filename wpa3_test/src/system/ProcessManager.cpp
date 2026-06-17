#include "system/ProcessManager.h"
#include <chrono>
#include <csignal>
#include <map>
#include <memory>
#include <ranges>
#include <regex>
#include <sstream>
#include <system_error>
#include <thread>
#include <unistd.h>
#include "inteprrupt.h"
#include "logger/error_log.h"
#include "system/utils.h"

namespace wpa3_tester{
using namespace std;
using namespace filesystem;
using namespace chrono;

void ProcessManager::start_drain_for(const string &process_name, const shared_ptr<ManagedProcess> &mp){
	if(!mp) return;
	mp->shutting_down = false;
	mp->drain_thread = thread([this, process_name, mp](){
		uint8_t buffer[4096];

		struct StreamInfo{
			reproc::stream stream;
			const char *label;
			int event;
		};
		constexpr StreamInfo streams[] = {
			{reproc::stream::out, "stdout", reproc::event::out}, {reproc::stream::err, "stderr", reproc::event::err}
		};

		bool natural_exit = false;
		while(!mp->shutting_down.load()){
			//log(LogLevel::DEBUG, "poll start "+process_name);
			auto [events, ec] = mp->proc->poll(reproc::event::out | reproc::event::err | reproc::event::exit,
												reproc::milliseconds(100));
			//log(LogLevel::DEBUG, "poll end "+process_name);
			if(mp->shutting_down) break;
			if(ec == errc::timed_out) continue;
			if(ec){
				if(ec == errc::broken_pipe || ec == errc::no_such_process){
					log(LogLevel::DEBUG, "Drain thread for {} finished (normal exit): {}", process_name, ec.message());
				} else{
					log(LogLevel::ERROR, "Drain thread for {} error: {} (code: {})", process_name, ec.message(),
						ec.value());
				}
				// flush remaining buffered data from pipes before exiting
				for(const auto &s: streams){
					while(true){
						auto [n, read_ec] = mp->proc->read(s.stream, buffer, sizeof(buffer));
						if(read_ec == errc::resource_unavailable_try_again || read_ec == errc::operation_would_block) break;
						if(read_ec || n == 0) break;
						handle_chunk(process_name, s.label, string(reinterpret_cast<char *>(buffer), n));
					}
				}
				natural_exit = true;
				break;
			}
			for(const auto &s: streams){
				if(!(events & s.event)) continue;

				while(true){
					auto [n, read_ec] = mp->proc->read(s.stream, buffer, sizeof(buffer));

					if(read_ec){
						if(read_ec == errc::resource_unavailable_try_again || read_ec == errc::operation_would_block){
							break;
						}
						break;
					}
					if(n == 0) break;
					handle_chunk(process_name, s.label, string(reinterpret_cast<char *>(buffer), n));
				}
			}
		}

		// flush subprocess pipe if process died naturally
		if(natural_exit){
			mp->naturally_exited = true;
			log(LogLevel::DEBUG, "flush start {}", process_name);
			for(const auto &[stream, label, event]: streams){
				if(mp->shutting_down.load()) break;
				const auto deadline = steady_clock::now() + milliseconds(500);
				while(!mp->shutting_down.load() && steady_clock::now() < deadline){
					const auto remaining = duration_cast<milliseconds>(deadline - steady_clock::now());
					if(auto [events, poll_ec] = mp->proc->poll(event, reproc::milliseconds(min(remaining.count(), milliseconds(50).count())));
						poll_ec || !(events & event)) break;

					auto [n, read_ec] = mp->proc->read(stream, buffer, sizeof(buffer));
					if(read_ec || n == 0) break;
					handle_chunk(process_name, label, string(reinterpret_cast<char *>(buffer), n));
				}
			}
			log(LogLevel::DEBUG, "flush done {}", process_name);
		}

		// flush incomplete (no trailing newline) lines and emit error if process died unexpectedly
		{
			lock_guard lock(logger_mtx);
			const string ts = current_timestamp();
			for(auto &[label, buf]: mp->logs.buffers){
				if(buf.empty()) continue;
				const string full_line = format("{} \"[{}] [{}] {}\"", ts, process_name, label, buf);
				buf.clear();
				if(combined_log.is_open()) write_log_line(combined_log, full_line);
				if(mp->logs.log.is_open()) write_log_line(mp->logs.log, full_line);
			}
			if(natural_exit && !mp->shutting_down.load()){
				const string err = format("{} [{}] [manager] ERROR: process exited unexpectedly", ts, process_name);
				if(combined_log.is_open()) write_log_line(combined_log, err);
				if(mp->logs.log.is_open()) write_log_line(mp->logs.log, err);
				log(LogLevel::ERROR, "Process '{}' exited unexpectedly", process_name);
			}
		}
		log(LogLevel::DEBUG, "Drain thread exited for {}", process_name);
	});
}

ProcessManager::~ProcessManager(){
	stop_all();
	lock_guard lock(logger_mtx);
	if(combined_log.is_open()) combined_log.close();
}

void ProcessManager::handle_chunk(
	//const shared_ptr<ManagedProcess>& mp,
	const string &process_name, const string &label, const string &data
){
	bool should_notify = false;
	{
		lock_guard lock(logger_mtx);
		const auto it = processes.find(process_name);
		if(it == processes.end() || !it->second){
			log(LogLevel::WARNING, "handle_chunk: process not found: {}", process_name);
			return;
		}
		const auto mp = it->second;
		auto &incomplete = mp->logs.buffers[label];
		incomplete += data;

		size_t pos;
		while((pos = incomplete.find('\n')) != string::npos){
			string line = incomplete.substr(0, pos);
			incomplete.erase(0, pos + 1);

			if(line.empty()) continue;

			const string full_line = format("{} [{}] [{}] {}", current_timestamp(), process_name, label, line);

			if(combined_log.is_open()) write_log_line(combined_log, full_line);
			if(mp->logs.log.is_open()) write_log_line(mp->logs.log, full_line);
			if(mp->logs.history_enabled) mp->logs.history += line + "\n";

			if(mp->logs.wait.pattern && regex_search(line, *mp->logs.wait.pattern)){
				log(LogLevel::DEBUG, "MATCH {} {}", process_name, line);
				mp->logs.wait.matched = true;
				should_notify = true;
			}
		}
	} // logger_mtx

	if(should_notify) wait_cv.notify_all();
}

void ProcessManager::run_dummy(const string &process_name){
	const auto mp = make_shared<ManagedProcess>();
	mp->proc = nullptr;
	mp->logs.history_enabled = true;

	const path log_path = log_base_dir / (process_name + ".log");
	mp->logs.log.open(log_path, ios::out | ios::trunc);
	set_public_perms(log_path);

	lock_guard lock(logger_mtx);
	processes[process_name] = mp;
}

void ProcessManager::run(const string &process_name, const vector<string> &cmd, const path &working_dir,
						const path &logging_dir
){
	if(const auto proc_it = processes.find(process_name); proc_it != processes.end()){
		throw run_err("This process already exists:" + process_name);
	}

	auto mp = make_shared<ManagedProcess>();
	mp->proc = make_shared<reproc::process>();

	reproc::options options{};
	options.stop.first = {reproc::stop::terminate, reproc::milliseconds(500)};
	options.stop.second = {reproc::stop::kill, reproc::milliseconds(500)};
	options.redirect.parent = false;

	path log_dir = log_base_dir;
	create_public_dirs(working_dir);

	string wd_string; //this need to be here, not in block, idk why
	if(!working_dir.empty()){
		wd_string = working_dir.string();
		options.working_directory = wd_string.c_str();
	}
	if(!logging_dir.empty()){ log_dir = logging_dir; }
	path log_path = log_dir / (process_name + ".log");

	log(LogLevel::DEBUG, "Starting process {}: {}'", process_name, join(cmd," "));

	// Initialize logs BEFORE starting process
	auto &logs = mp->logs;
	logs.log.close();
	logs.log.open(log_path, ios::out | ios::trunc);
	logs.history.clear();
	logs.history_enabled = true;

	if(!logs.log.is_open()){ throw config_err("Failed to open log for {}:{}", process_name, log_path.string()); }
	set_public_perms(log_path);

	{
		lock_guard lock(logger_mtx);
		processes[process_name] = mp;
	}

	vector<string> cmd_with_setsid;
	cmd_with_setsid.emplace_back("setsid");  // crate new group to kill all with subprocesses
	cmd_with_setsid.insert(cmd_with_setsid.end(), cmd.begin(), cmd.end());

	if(const auto ec = mp->proc->start(cmd_with_setsid, options)){
		{
			lock_guard lock(logger_mtx);
			processes.erase(process_name);
		}
		throw run_err(format("Failed to start {}: {}", process_name, ec.message()));
	}

	// Put the child in its own process group so killpg kills the whole tree.
	const pid_t child_pid = mp->proc->pid().first;
	(void)setpgid(child_pid, child_pid);
	mp->pgid = child_pid;
	mp->start_pid = child_pid;

	start_drain_for(process_name, mp);

	const string line = format("{} [{}] [cmd] {}", current_timestamp(), process_name, join(cmd, " "));
	lock_guard lock(logger_mtx);
	if(combined_log.is_open()){ write_log_line(combined_log, line); }
	if(logs.log.is_open()){ write_log_line(logs.log, line); }
}

bool ProcessManager::wait_for(const string &actor_name, const string &pattern, const seconds timeout,
							const bool throw_err
){
	log(LogLevel::DEBUG, "WAIT pattern: {}", pattern);
	shared_ptr<ManagedProcess> mp;
	{
		lock_guard lock(logger_mtx);
		const auto it = processes.find(actor_name);
		if(it == processes.end() || !it->second)
			throw run_err("Unknown process in wait_for: " + actor_name);
		mp = it->second;
		auto &logs = mp->logs;

		logs.wait.pattern = regex(pattern);
		logs.wait.matched = false;

		stringstream ss(logs.history);
		string line;
		while(getline(ss, line)){
			if(regex_search(line, *logs.wait.pattern)){
				log(LogLevel::DEBUG, "MATCH in history {} {}", actor_name, line);
				logs.history.clear();
				logs.wait.pattern = nullopt;
				return true;
			}
		}
	}

	unique_lock cv_lock(wait_mutex);
	auto &logs = mp->logs;
	bool pred_met = false;
	const auto deadline = steady_clock::now() + timeout;
	while (!pred_met && !g_interrupted.load()) {
		const auto remaining = duration_cast<nanoseconds>(deadline - steady_clock::now());
		if (remaining <= nanoseconds(0)) break;
		pred_met = wait_cv.wait_for(cv_lock, min(remaining, nanoseconds(milliseconds(50))),
			[&logs, &mp]{ return logs.wait.matched || mp->shutting_down.load(); });
	}

	lock_guard data_lock(logger_mtx);
	logs.wait.pattern = nullopt;

	if(g_interrupted.load() && !logs.wait.matched){
		log(LogLevel::DEBUG, "wait_for for '{}' interrupted: Ctrl+C", actor_name);
		return false;
	}
	if(mp->shutting_down.load() && !logs.wait.matched){
		log(LogLevel::DEBUG, "wait_for for '{}' interrupted: process stopped", actor_name);
		return false;
	}
	if(!pred_met){
		if(throw_err)
			throw timeout_err("Timeout waiting for pattern '{}' in process '{}' (timeout: {} seconds)",
							pattern, actor_name, static_cast<int>(timeout.count()));
		return false;
	}
	logs.history.clear();
	return true;
}

void ProcessManager::stop(const string &process_name) noexcept{
	//log(LogLevel::DEBUG, "stop() called for "+process_name);
	shared_ptr<ManagedProcess> mp;
	{
		lock_guard lock(logger_mtx);
		const auto proc_iter = processes.find(process_name);
		if(proc_iter == processes.end()) return;

		mp = proc_iter->second;
		write_log_line(mp->logs.log, "@END_STOP");

		// clean up wait state and notify any waiting threads
		mp->logs.history_enabled = false;
		mp->shutting_down = true;
	}
	wait_cv.notify_all();

	reproc::stop_actions operations{};
	operations.first = {reproc::stop::terminate, reproc::milliseconds(500)};
	operations.second = {reproc::stop::kill, reproc::milliseconds(500)};

	if(!mp->naturally_exited){
		if(mp->pgid > 0){
			(void)killpg(mp->pgid, SIGTERM);
			(void)killpg(mp->pgid, SIGKILL);
		} else if(mp->proc){
			[[maybe_unused]] const auto ec_t = mp->proc->terminate();
			[[maybe_unused]] const auto ec_k = mp->proc->kill();
		}
	}

	if(mp->drain_thread.joinable()) mp->drain_thread.join();

	// erase after drain thread exits so flush-phase handle_chunk calls still find the process
	{
		lock_guard lock(logger_mtx);
		processes.erase(process_name);
	}

	// Call on_stop callback if registered
	if(mp->before_stop_callback){
		try{
			mp->before_stop_callback();
		} catch(const exception &e){
			log(LogLevel::WARNING, "Error in on_stop callback for  {}:{}", process_name, e.what());
		}
	}

	if(mp->proc){
		if(mp->naturally_exited){
			// Collect exit status so reproc destructor doesn't attempt a redundant stop/close.
			reproc::stop_actions wait_only{};
			wait_only.first = {reproc::stop::wait, reproc::milliseconds(100)};
			(void)mp->proc->stop(wait_only);
		} else{
			(void)mp->proc->stop(operations);
		}
	}
	log(LogLevel::DEBUG, "proc->stop done for {}", process_name);

	// Call on_stop callback if registered
	if(mp->after_stop_callback){
		try{
			mp->after_stop_callback();
		} catch(const exception &e){
			log(LogLevel::WARNING, "Error in on_stop callback for {}:{}", process_name, e.what());
		}
	}
}

void ProcessManager::before_stop(const string &process_name, const function<void()> &callback){
	lock_guard lock(logger_mtx);
	const auto proc_iter = processes.find(process_name);
	if(proc_iter != processes.end() && proc_iter->second){
		proc_iter->second->before_stop_callback = callback;
	}
}

void ProcessManager::after_stop(const string &process_name, const function<void()> &callback){
	lock_guard lock(logger_mtx);
	if(const auto proc_iter = processes.find(process_name); proc_iter != processes.end() && proc_iter->second){
		proc_iter->second->after_stop_callback = callback;
	}
}

void ProcessManager::stop_all(){
	vector<string> process_names;
	{
		lock_guard lock(logger_mtx);
		process_names.reserve(processes.size());
		for(const auto &name: processes | views::keys){ process_names.push_back(name); }
	}

	for(const auto &process_name: process_names)
		stop(process_name);
	log(LogLevel::DEBUG, "All processes stopped");
}
}