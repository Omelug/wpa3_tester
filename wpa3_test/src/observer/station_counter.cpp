#include "observer/station_counter.h"
#include <algorithm>
#include <cstdio>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "observer/observers.h"
#include "system/utils.h"

namespace wpa3_tester::observer::station_counter{
using namespace std;
using namespace filesystem;

const string program_name = "station_counter";

static string build_count_script(const string &iface, const string &log_file, int interval_sec, bool append) {
	const string write_cmd = append ? ">> " + log_file : "";
	return "while true; do count=$(iw dev " + iface + " station dump 2>/dev/null"
		   "| grep -c '^Station' || echo 0); "
		   "echo \"$(date +%s) $count\" " + write_cmd + "; "
		   "sleep " + to_string(interval_sec) + "; done";
}

static void validate_interface(const string &iface) {
	const string check_cmd = "iw dev " + iface + " station dump 2>&1";
	FILE *pipe = popen(check_cmd.c_str(), "r");
	if (!pipe) {
		throw run_err("station_counter: popen failed for iw on iface " + iface);
	}
	char buf[256] = {};
	fgets(buf, sizeof(buf), pipe);
	pclose(pipe);

	const string output(buf);
	if (output.find("No such device") != string::npos || 
		output.find("command failed") != string::npos) {
		throw run_err("station_counter: interface '" + iface + "' not found or not an AP interface.");
	}
}

void start_remote(RunStatus &rs, const string &actor_name, int interval_sec, const string &local_log){
	const auto &actor = rs.get_actor(actor_name);
	const string iface = actor.get(SK::iface);

	const string remote_log = "/tmp/" + actor_name + SUFFIX_sta + ".log";
	const string pid_file = remote_log + ".pid";

	const string script = build_count_script(iface, remote_log, interval_sec, true);
	actor->conn->exec("sh -c '" + script + "' & echo $! > " + pid_file, false);

	actor->conn->on_disconnect([remote_log, local_log, actor, pid_file](){
		actor->conn->exec("kill $(cat " + pid_file + "); rm " + pid_file);
		actor->conn->download_file(remote_log, local_log);
		actor->conn->exec("rm " + remote_log);
	});
}

void start_local(RunStatus &rs, const string &actor_name, const string &iface, int interval_sec) {
	validate_interface(iface);

	const string log_dir = get_observer_folder(rs, program_name);
	const string script = build_count_script(iface, "", interval_sec, false);

	rs.process_manager.run(actor_name + SUFFIX_sta, {"sh", "-c", script}, {}, log_dir);
}

void start_station_monitoring(RunStatus &rs, const string &actor_name, const int interval_sec) {
	const auto actor = rs.get_actor(actor_name);
	const string local_log = get_observer_folder(rs, program_name) / (actor_name + SUFFIX_sta + ".log");
	const string iface = actor.get(SK::iface);

	if (actor->conn != nullptr) {
		start_remote(rs, actor_name, interval_sec, local_log);
	} else {
		start_local(rs, actor_name, iface, interval_sec);
	}
}

static void setup_station_graph(Graph &g, const string &output_path, double max_y) {
	g.ymin = 0.0;
	g.ymax = max_y;

	g.file = popen("gnuplot", "w");
	if (!g.file) throw run_err("Failed to start gnuplot");

	g.gpcmd("set terminal pngcairo size 1600,600 enhanced font 'Arial,10'");
	g.gpcmd("set output '" + output_path + "'");
	g.gpcmd("set datafile commentschars '#'");
	g.gpcmd("set xdata time");
	g.gpcmd("set timefmt '%s'");
	g.gpcmd("set format x '%M:%S'");
	g.gpcmd("set xtics rotate by -45");
	g.gpcmd("set ylabel 'Connected Stations'");
	g.gpcmd("set ytics 1");
	g.gpcmd("set grid");
	g.gpcmd("set key outside");
	g.gpcmd("set tmargin 5");
	g.gpcmd("set bmargin 5");
	g.gpcmd(escape_tex("set title 'Station Count'"));
}

void generate_station_graph(const string &data_filepath, const string &output_imagepath, const G_elms &elements) {
	vector<LogTimePoint> times;
	vector<double> sta_count;
	double max_stations = 1.0;

	ifstream f(data_filepath);
	for (string line; getline(f, line); ) {
		if (line.empty()) continue;
		istringstream iss(line);
		long long ts;
		double count;
		if (iss >> ts >> count) {
			max_stations = max(max_stations, count);
			times.emplace_back(chrono::seconds(ts));
			sta_count.push_back(count);
		}
	}

	auto g = Graph();
	setup_station_graph(g, output_imagepath, max_stations);

	auto all_elements = clone_elements(elements);
	all_elements.push_back(make_unique<GraphXYPoints>(times, sta_count, "stations", "blue"));
	g.add_graph_elements(all_elements);

	if (!times.empty()) {
		const long long x_min = chrono::system_clock::to_time_t(times.front());
		const long long x_max = chrono::system_clock::to_time_t(times.back());
		g.gpcmd("set xrange ['" + to_string(x_min) + "':'" + to_string(x_max + 10) + "']");
	}
	g.render();
	set_public_perms(output_imagepath);
}

void create_station_graph(const RunStatus &rs, const string &actor_name, const G_elms &elements) {
	path log_path = get_observer_folder(rs, program_name) / (actor_name + SUFFIX_sta + ".log");
	set_public_perms(log_path);
	const path output = log_path.replace_extension(".png");
	remove(output);
	generate_station_graph(log_path.string(), output.string(), elements);
}
}
