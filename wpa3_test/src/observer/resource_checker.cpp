#include "observer/resource_checker.h"
#include <filesystem>
#include <string>
#include <vector>
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "observer/observers.h"
#include "observer/tshark_wrapper.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::observer::resource_checker{
using namespace std;
using namespace filesystem;
const string program_name = "resource_checker";

void start_resource_monitoring_remote(RunStatus &rs, const string &actor_name, const string &iface,
                                      const int interval_sec, const string &local_log
){
    const auto &actor = rs.get_actor(actor_name);
    const string local_script = (path(PROJECT_ROOT_DIR) / "awk_scripts/monitor.awk").string();
    const string remote_script = "/tmp/monitor_" + actor_name + ".awk";
    string remote_log = "/tmp/" + actor_name + SUFFIX_res + ".log";
    const string pid_file = remote_log + ".pid";

    actor->conn->upload_script_raw(local_script, remote_script);
    const string stat_cmd = "awk -v delay=" + to_string(interval_sec) +
            " -v iface='" + iface + "' -f " + remote_script +
            " > " + remote_log + " 2>&1 & echo $! > " + pid_file;
    actor->conn->exec(stat_cmd, false);
    actor->conn->on_disconnect([remote_log, local_log, actor, pid_file](){
        actor->conn->exec("kill $(cat " + pid_file + "); rm " + pid_file);
        actor->conn->download_file(remote_log, local_log);
        actor->conn->exec("rm " + remote_log);
    });
}

void start_resource_monitoring(RunStatus &rs, const string &actor_name, const int interval_sec){
    const auto actor = rs.get_actor(actor_name);
    const string local_log = get_observer_folder(rs, program_name) / (actor_name + SUFFIX_res + ".log");

    if(actor->conn != nullptr){
        start_resource_monitoring_remote(rs, actor_name, actor["iface"], interval_sec, local_log);
        return;
    }

    const int target_pid = rs.process_manager.get_pid(actor_name);
    const string log_dir = get_observer_folder(rs, program_name);

    const vector<string> command = {
        "pidstat",
        //"-T", "CHILD",
        "-h",
        "-p", to_string(target_pid),
        "-u",                   // cpu statistic
        "-r",                   // ram statistics
        to_string(interval_sec) // interval
    };
    rs.process_manager.run(actor_name + SUFFIX_res, command, get_observer_folder(rs, program_name), log_dir);
}

vector<ResourceRecord> parse_resource_log(const string &filepath){
    vector<ResourceRecord> records;
    ifstream file(filepath);
    string line;
    int n_cores = -1;

    while(getline(file, line)){
        if(line.empty()) continue;

        // Parse header to get core count
        if(line[0] == '#'){
            // count "cpu" prefixed tokens
            istringstream h(line);
            string tok;
            n_cores = 0;
            while(h >> tok) if(tok.rfind("cpu", 0) == 0) ++n_cores;
            continue;
        }

        if(n_cores < 0) continue; // no header yet

        istringstream iss(line);
        ResourceRecord record;
        if(!(iss >> record.timestamp)) continue;

        record.core_percents.resize(n_cores);
        for(int i = 0; i < n_cores; ++i) if(!(iss >> record.core_percents[i])) goto skip;

        if(!(iss >> record.mem_free_kb)) continue;
        if(!(iss >> record.airtime_pct)) continue;
        if(!(iss >> record.rx_drops)) continue;

        records.push_back(record);
    skip:;
    }
    return records;
}

void create_resource_monitor_graph(const string &data_filepath, const vector<unique_ptr<GraphElements>> &elements){
    const string output_imagepath = path(data_filepath).replace_extension(".png").string();
    vector<ResourceRecord> resources = parse_resource_log(data_filepath);
    remove(output_imagepath);
    generate_resource_graph(data_filepath, output_imagepath, elements); //TODO ACM events
}

//*-------------  ONLY ONE PID ----------------
void parse_pid_log(const string &data_filepath, const string &csv_outputpath){
    ifstream infile(data_filepath);
    ofstream outfile(csv_outputpath);
    string line;

    outfile << "Timestamp,CPU_Pct,RSS,Mem_Pct" << endl;

    while(getline(infile, line)){
        if(line.find("[stdout]") != string::npos){
            stringstream ss(line);
            string timestamp_iso, res_tag, stream_tag, time_hhmmss;
            ss >> timestamp_iso >> res_tag >> stream_tag >> time_hhmmss;

            if(time_hhmmss.find(':') != string::npos){
                vector<string> tokens;
                string val;
                tokens.push_back(time_hhmmss);
                while(ss >> val) tokens.push_back(val);

                // tokens[7] = %CPU, tokens[13] = RSS, tokens[14] = %MEM
                if(tokens.size() > 14){
                    outfile << timestamp_iso << ","
                            << tokens[7] << ","
                            << tokens[13] << ","
                            << tokens[14] << endl;
                }
            }
        }
    }
}

void generate_pid_graph(const string &csv_filepath, const string &output_imagepath){
    string gnuplot_cmd = "gnuplot -e \"";
    gnuplot_cmd += "set datafile separator ','; ";
    gnuplot_cmd += "set terminal pngcairo size 1000,600; ";
    gnuplot_cmd += "set output '" + output_imagepath + "'; ";
    gnuplot_cmd += "set title 'Resource Usage (pidstat)'; ";
    gnuplot_cmd += "set xdata time; ";
    gnuplot_cmd += "set timefmt '%Y-%m-%dT%H:%M:%S'; ";
    gnuplot_cmd += "set format x '%H:%M:%S'; ";
    gnuplot_cmd += "set xlabel 'Time'; ";
    gnuplot_cmd += "set ylabel '% Usage / MB'; ";
    gnuplot_cmd += "plot '" + csv_filepath + "' using 1:2 with lines title '% CPU', ";
    gnuplot_cmd += "     '' using 1:4 with lines title '% MEM';\"";

    const int result = system(gnuplot_cmd.c_str());
    if(result != 0){
        throw stats_err("Pid graph gnuplot failed");
    }
}

void create_resource_pid_graph(const string &data_filepath){
    const string output_imagepath = path(data_filepath).replace_extension(".png").string();
    const string csv_file = path(data_filepath).replace_extension(".csv").string();
    parse_pid_log(data_filepath, csv_file);
    generate_pid_graph(csv_file, output_imagepath);
}

void generate_resource_graph(const std::string &data_filepath, const std::string &output_imagepath,
                             const vector<unique_ptr<GraphElements>> &elements
){
    ifstream file(data_filepath);
    string first_line, second_line;
    getline(file, first_line);
    getline(file, second_line);
    file.close();

    int num_columns = 0;
    {
        istringstream iss(second_line);
        string t;
        while(iss >> t) num_columns++;
    }
    int num_cores = max(1, num_columns - 4);
    int ram_col = num_cores + 2;

    auto g = Graph();
    g.ymin = 0.0;
    g.ymax = 100.0;
    //graph.start_time = ;

    g.file = popen("gnuplot", "w");
    if(!g.file) throw runtime_error("Failed to start gnuplot");

    g.gpcmd("set datafile commentschars '#'");
    g.gpcmd("set terminal pngcairo size 1600,600");
    g.gpcmd("set output '" + output_imagepath + "'");
    g.gpcmd("set xdata time");
    g.gpcmd("set timefmt '%s'");
    g.gpcmd("set format x '%M:%S'");
    g.gpcmd("set xtics rotate by -45");
    g.gpcmd("set ytics nomirror");
    g.gpcmd("set y2tics");
    g.gpcmd("set ylabel 'CPU Usage (%%)' ");
    g.gpcmd("set yrange [0:100]");
    g.gpcmd("set y2label 'Free Memory (KB)'");
    g.gpcmd("set y2range [0:*]");
    g.gpcmd("set grid");
    g.gpcmd("set key outside");

    for(int i = 0; i < num_cores; ++i){
        g.plot_parts.push_back(
            "'" + data_filepath + "' using 1:" + to_string(i + 2)
            + " with lines lw 2 title 'Core " + to_string(i) + " %' axes x1y1");
    }

    g.plot_parts.push_back(
        "'" + data_filepath + "' using 1:" + to_string(ram_col)
        + " with lines lw 2 dt 2 title 'Free RAM' axes x1y2");

    g.add_graph_elements(elements);
    g.render();
}

void create_graph(const RunStatus &rs, const string &source,
                  const std::vector<std::unique_ptr<GraphElements>> &elements
){
    const auto log_path = get_observer_folder(rs, "resource_checker") / ("access_point" + SUFFIX_res + ".log");
    if(source == "external") create_resource_monitor_graph(log_path, elements);
    if(source == "internal") create_resource_pid_graph(log_path);
}
}