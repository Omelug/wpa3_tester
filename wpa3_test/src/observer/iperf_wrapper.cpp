#include "observer/iperf_wrapper.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "observer/observers.h"
#include "overview/described.h"
#include "system/hw_capabilities.h"
#include "visual/result_helper.h"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <optional>

namespace wpa3_tester::observer{
using namespace std;
using namespace filesystem;

IperfData parse_iperf_log(const path &log_path, const string &actor_tag){
	IperfData data;
	ifstream ifs(log_path);
	if(!ifs.is_open()) return data;

	string line;
	while(getline(ifs, line)){
		if(line.find("[" + actor_tag + "]") == string::npos) continue;
		if(line.find("[cmd]") != string::npos) continue;
		if(line.find("- - - - - - - - - - -") != string::npos) break;
		const auto pos_rate = line.find("Kbits/sec");
		if(pos_rate == string::npos) continue;

		size_t end = pos_rate;
		while(end > 0 && isspace(line[end - 1])) --end;
		size_t start = end;
		while(start > 0 && (isdigit(line[start - 1]) || line[start - 1] == '.')) --start;

		try{
			double bw = stod(line.substr(start, end - start));
			data.bandwidths.push_back(bw);
			data.intervals.push_back(static_cast<double>(data.bandwidths.size()));
		} catch(...) {
			log(LogLevel::ERROR, "iperf parsing error");
		}
	}
	return data;
}

static void render_graph(const IperfData &data, const string &label, const path &output_path){
	if(data.bandwidths.empty() || data.intervals.empty()) return;

	FILE *gp = popen("gnuplot", "w");
	if(!gp){ throw run_err("Could not open pipe to gnuplot. Is it installed?"); }

	const string ext = output_path.extension().string();
	if(ext == ".png"){
		fprintf(gp, "set terminal pngcairo size 800,600\n");
	} else if(ext == ".svg"){
		fprintf(gp, "set terminal svg size 800,600\n");
	} else{
		fprintf(gp, "set terminal pdf\n");
	}

	fprintf(gp, "set output '%s'\n", output_path.c_str());
	fprintf(gp, "set title 'Iperf Throughput: %s'\n", label.c_str());
	fprintf(gp, "set xlabel 'Sample [ms]'\n");
	fprintf(gp, "set ylabel 'Throughput [Kbit/s]'\n");
	fprintf(gp, "set logscale y\n");
	fprintf(gp, "set grid\n");

	fprintf(gp, "plot '-' with lines lw 2 title '%s'\n", label.c_str());

	for(size_t i = 0; i < data.bandwidths.size(); ++i){
		fprintf(gp, "%f %f\n", data.intervals[i], data.bandwidths[i]);
	}

	fprintf(gp, "e\n");
	pclose(gp);
}

void iperf3_graph(const path &log_path, const string &actor_tag, const string &output_png){
	if(!exists(log_path)){ throw config_err("iperf3 log file not found: " + log_path.string()); }

	const IperfData data = parse_iperf_log(log_path, actor_tag);
	if(data.bandwidths.empty()){
		log(LogLevel::WARNING, "No samples parsed for: {}", actor_tag);
		return;
	}

	const path full_output_path = log_path.parent_path() / output_png;
	try{
		render_graph(data, actor_tag, full_output_path);
		log(LogLevel::INFO, "Graph saved via {}", full_output_path.string());
	} catch(const exception &e){
		log(LogLevel::ERROR, "Rendering failed: {}", e.what());
	}
}

constexpr string program_name = "iperf3";

//TODO check on overview
optional<GraphXYPoints> iperf_log_to_xy(const path &log_path, const string &label, const string &color){
	if(!exists(log_path)) return nullopt;

	ifstream f(log_path);
	string line;
	vector<LogTimePoint> x_times;
	vector<double> y_vals;

	while(getline(f, line)){
		if(line.find("- - - -") != string::npos) break;
		if(line.find("sender") != string::npos || line.find("receiver") != string::npos) continue;
		if(line.find("sec") == string::npos) continue;

		const auto bracket = line.find(']');
		if(bracket == string::npos) continue;
		float iv_start = 0;
		if(sscanf(line.c_str() + bracket + 1, " %f-", &iv_start) != 1) continue;

		auto extract_bw = [&](const size_t  unit_pos) -> double {
			size_t end = unit_pos;
			while(end > 0 && isspace(static_cast<unsigned char>(line[end - 1]))) --end;
			size_t start = end;
			while(start > 0 && (isdigit(static_cast<unsigned char>(line[start - 1])) || line[start - 1] == '.')) --start;
			if(start == end) return -1.0;
			try{ return stod(line.substr(start, end - start)); } catch(...){ return -1.0; }
		};

		double bw_mbits;
		if(const auto pos = line.rfind("Mbits/sec"); pos != string::npos){
			bw_mbits = extract_bw(pos);
		} else if(const auto unit_pos = line.rfind("Kbits/sec"); unit_pos != string::npos){
			const double v = extract_bw(unit_pos);
			bw_mbits = (v < 0) ? v : v / 1000.0;
		} else continue;

		if(bw_mbits < 0) continue;

		const auto dur = chrono::duration_cast<chrono::nanoseconds>(chrono::duration<double>(iv_start));
		x_times.emplace_back(dur);
		y_vals.push_back(bw_mbits);
	}

	if(x_times.empty()) return nullopt;
	return GraphXYPoints(x_times, y_vals, label, color, YAxis::Y2, 0.0, 15.0);
}

static void kill_iperf3_port(const RunStatus &rs, const string &actor_name){
	vector<string> kill_cmd;
	add_nets_header(rs, kill_cmd, actor_name);
	kill_cmd.insert(kill_cmd.end(), {"fuser", "-k", "5201/tcp"});
	string cmd;
	for (const auto &p : kill_cmd) cmd += p + " ";
	system((cmd + "2>/dev/null").c_str());
}

void start_iperf3(RunStatus &rs, const string &actor_name, const string &src_name, const string &dst_name){
	kill_iperf3_port(rs, src_name);
	vector<string> command = {};
	add_nets_header(rs, command, src_name);
	command.insert(command.end(), {
						"stdbuf", "-oL", "-eL", // disable buffering for immediate output
						program_name, "-B", rs.config().at("actors").at(src_name).at("ip_addr"), "-c",
						rs.config().at("actors").at(dst_name).at("ip_addr"),
						//"-u", //dát do observer config
						"--bidir", "-b", "10M", "-t", "0" // infinity
					});
	const path obs = get_observer_folder(rs, program_name);
	rs.process_manager.run(actor_name, command, obs, obs);
}

void start_iperf3_server(RunStatus &rs, const string &actor_name, const string &server_name){
	const auto server_actor = rs.get_actor(server_name);
	if(server_actor->is_external_WB()){
		// process_manager is local-only; start iperf3 daemon on remote via existing SSH conn
		server_actor->conn->exec("killall iperf3 2>/dev/null; rm -f /tmp/iperf3_ap_server.log; iperf3 -s -p 5201 -D --timestamps --logfile /tmp/iperf3_ap_server.log 2>&1");
		log(LogLevel::DEBUG, "iperf3 server daemon started on {} via SSH", server_name);
		const path log_file = get_observer_folder(rs, program_name) / (actor_name + ".log");
		auto conn = server_actor->conn;
		// Register dummy so stop_all() triggers after_stop while SSH is still alive
		rs.process_manager.run_dummy(actor_name);
		rs.process_manager.after_stop(actor_name, [conn, log_file](){
			conn->exec("killall iperf3 2>/dev/null");
			conn->download_file("/tmp/iperf3_ap_server.log", log_file);
		});
		return;
	}
	kill_iperf3_port(rs, server_name);
	vector<string> command = {};
	add_nets_header(rs, command, server_name);
	command.insert(command.end(), {
						"stdbuf", "-oL", "-eL",
						program_name, "-s",
						"-p", "5201",
					});
	const path obs = get_observer_folder(rs, program_name);
	rs.process_manager.run(actor_name, command, obs, obs);
}

static constexpr int ZERO_STREAK_THRESHOLD = 5; // stable/down iperf

described_str iperf_log_has_zero_plain(const path &log_path, const TimeWindow &window){
	if(!exists(log_path)) return {};
	ifstream f(log_path);
	string line;
	int streak = 0, max_streak = 0;
	bool any_zero = false;
	float last_iv = -999.0f;
	bool cur_iv_zero = false;

	// Commit the accumulated zero-status of the previous interval and reset.
	// OR across all TX/RX lines of the same interval (bidir mode has two lines per second).
	auto commit = [&]{
		if(last_iv < -900.0f) return;
		if(cur_iv_zero){ ++streak; max_streak = max(max_streak, streak); any_zero = true; }
		else            { streak = 0; }
		cur_iv_zero = false;
	};

	while(get_line_in_window(f, line, window)){
		if(line.find("- - - -") != string::npos) break;
		// Use rfind(']') to skip timestamp/process-name prefix and find the stream role bracket
		const auto bracket = line.rfind(']');
		if(bracket == string::npos) continue;
		float iv = -1.0f;
		if(sscanf(line.c_str() + bracket + 1, " %f-", &iv) != 1 || iv < 0) continue;
		if(iv != last_iv){ commit(); last_iv = iv; }
		if(line.find("0.00 Bytes") != string::npos) cur_iv_zero = true;
	}
	commit();

	described_str r;
	if(max_streak >= ZERO_STREAK_THRESHOLD)
		r += {"down",     "iperf3 down (>="  + to_string(ZERO_STREAK_THRESHOLD) + "s)"};
	else if(any_zero)
		r += {"unstable", "iperf3 unstable (<" + to_string(ZERO_STREAK_THRESHOLD) + "s outage)"};
	return r;
}

described_str iperf_was_down(RunStatus &rs, const path &test_folder){
	const path dir = test_folder / "observer" / "iperf3";
	const path ap  = dir / "ap_iperf3_server.log";
	const path cl  = dir / "client_iperf3_gen.log";
	if(!exists(ap) && !exists(cl)) return {};

	const auto sev = [](const described_str &r) -> int {
		return r.value() == "down" ? 2 : r.value() == "unstable" ? 1 : 0;
	};
	const auto ap_r = iperf_log_has_zero_plain(ap, visual::helper::get_run_window(rs, rs.get_actor("ap")));
	const auto cl_r = iperf_log_has_zero_plain(cl, visual::helper::get_run_window(rs, rs.get_actor("client")));
	// Add less severe first so value() (last pair) == worst
	described_str result;
	if(sev(ap_r) <= sev(cl_r)){
		if(!ap_r.empty()) result += ap_r.last();
		if(!cl_r.empty()) result += cl_r.last();
	} else {
		if(!cl_r.empty()) result += cl_r.last();
		if(!ap_r.empty()) result += ap_r.last();
	}
	return result;
}
}