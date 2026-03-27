#include "observer/resource_checker.h"
#include <filesystem>
#include <string>
#include <vector>
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "observer/observers.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::observer::resource_checker{
    using namespace std;
    using namespace filesystem;
    const string program_name = "resource_checker";

    void start_resource_monitoring_remote(RunStatus &rs, const string &actor_name, const string &iface, const int interval_sec, const string &local_log) {
        const auto& actor = rs.get_actor(actor_name);
        const string local_script = (path(PROJECT_ROOT_DIR) / "awk_scripts/monitor.awk").string();
        const string remote_script = "/tmp/monitor_" + actor_name + ".awk";
        string remote_log = "/tmp/" + actor_name + SUFFIX_res + ".log";
        const string pid_file = remote_log + ".pid";

        actor->conn->upload_script_raw(local_script, remote_script);
        const string stat_cmd = "awk -v delay=" + to_string(interval_sec) +
                          " -v iface='" + iface + "' -f " + remote_script +
                          " > " + remote_log + " 2>&1 & echo $! > " + pid_file;
        actor->conn->exec(stat_cmd, false);

        rs.process_manager.on_stop(actor_name+SUFFIX_res, [remote_log, local_log, actor, pid_file]() {
            actor->conn->exec("kill $(cat " + pid_file + "); rm " + pid_file);
            actor->conn->download_file(remote_log, local_log);
            actor->conn->exec("rm " + remote_log);
        });
    }


    void start_resource_monitoring(RunStatus &rs, const string &actor_name, const int interval_sec) {
        const auto actor = rs.get_actor(actor_name);
        const string local_log = get_observer_folder(rs, program_name) / (actor_name+SUFFIX_res+".log");

        if (actor->conn != nullptr) {
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
            "-u", // cpu statistic
            "-r", // ram statistics
            to_string(interval_sec) // interval
        };
        rs.process_manager.run(actor_name+SUFFIX_res, command, get_observer_folder(rs, program_name), log_dir);

    }

    vector<ResourceRecord> parse_resource_log(const string& filepath) {
        vector<ResourceRecord> records;
        ifstream file(filepath);
        string line;

        while (getline(file, line)) {
            if (line.empty()) continue;

            istringstream iss(line);
            ResourceRecord record;
            if (!(iss >> record.timestamp)) continue;
            int val;
            vector<int> temp_vals;
            while (iss >> val) {temp_vals.push_back(val);}

            // minimum 3 values: RAM, Airtime, Drops
            if (temp_vals.size() < 3) continue;

            //  last is RX Drops
            record.rx_drops = temp_vals.back();
            temp_vals.pop_back();

            // last-1 Airtime %
            record.airtime_pct = temp_vals.back();
            temp_vals.pop_back();

            // last -2 Free RAM kB
            record.mem_free_kb = temp_vals.back();
            temp_vals.pop_back();

            // rest are stats aboutCPU
            record.core_percents = temp_vals;

            records.push_back(record);
        }
        return records;
    }

    /* TODO void start_ping_monitoring_remote(RunStatus &rs, const string &client_actor_name, const string &target_ip, int interval_sec) {
        const auto& actor = rs.get_actor(client_actor_name);
        const string remote_log = "/tmp/" + client_actor_name + "_ping.log";
        const string local_log = get_observer_folder(rs, program_name) / (client_actor_name + "_ping.log");

        const string ping_cmd =
            "while true; do "
            "now=$(date +%s); "
            "res=$(ping -c 1 -W 1 " + target_ip + " | awk -F'time=' '/time=/ {print $2}' | awk '{print $1}'); "
            "if [ -z \"$res\" ]; then res=\"-1\"; fi; "
            "echo \"$now $res\"; "
            "sleep " + to_string(interval_sec) + "; "
            "done > " + remote_log;

        const vector<string> ssh_command = {
            "sshpass", "-p", actor["ssh_password"],
            "ssh", "-o", "StrictHostKeyChecking=no", actor["ssh_user"] + "@" + actor["whitebox_ip"], ping_cmd
        };

        rs.process_manager.run(client_actor_name + "_ping", ssh_command, get_observer_folder(rs, program_name));
        rs.process_manager.on_stop(client_actor_name + "_ping", [remote_log, local_log, actor]() {
            hw_capabilities::run_cmd({"sshpass", "-p", actor["ssh_password"], "scp", "-O", actor["ssh_user"] + "@" + actor["whitebox_ip"] + ":" + remote_log, local_log});
            actor->conn->exec("rm " + remote_log);
        });
    }*/

    void create_resource_monitor_graph(const string& data_filepath){
        const string output_imagepath = path(data_filepath).replace_extension(".png").string();
        vector<ResourceRecord> resources = parse_resource_log(data_filepath);
        generate_resource_graph(data_filepath, output_imagepath, {}); //TODO ACM events
    }

    //*-------------  ONLY ONE PID ----------------
    void parse_pid_log(const string& data_filepath, const string& csv_outputpath) {
        ifstream infile(data_filepath);
        ofstream outfile(csv_outputpath);
        string line;

        outfile << "Timestamp,CPU_Pct,RSS,Mem_Pct" << endl;

        while (getline(infile, line)) {
            if (line.find("[stdout]") != string::npos) {
                stringstream ss(line);
                string timestamp_iso, res_tag, stream_tag, time_hhmmss;
                ss >> timestamp_iso >> res_tag >> stream_tag >> time_hhmmss;

                if (time_hhmmss.find(':') != string::npos) {
                    vector<string> tokens;
                    string val;
                    tokens.push_back(time_hhmmss);
                    while (ss >> val) tokens.push_back(val);

                    // tokens[7] = %CPU, tokens[13] = RSS, tokens[14] = %MEM
                    if (tokens.size() > 14) {
                        outfile << timestamp_iso << ","
                                << tokens[7] << ","
                                << tokens[13] << ","
                                << tokens[14] << endl;
                    }
                }
            }
        }
    }

    void generate_pid_graph(const string& csv_filepath, const string& output_imagepath) {
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
        if (result != 0){
            throw stats_err(" Pid graph gnuplot failed");
        }
    }

    void create_resource_pid_graph(const string& data_filepath){
        const string output_imagepath = path(data_filepath).replace_extension(".png").string();
        const string csv_file = path(data_filepath).replace_extension(".csv").string();
        parse_pid_log(data_filepath, csv_file);
        generate_pid_graph(csv_file, output_imagepath);
    }

    void generate_resource_graph(const string& data_filepath,
                             const string& output_imagepath,
                             const vector<long long>& acm_timestamps) {

        // Read the first line to dynamically calculate the number of cores
        ifstream file(data_filepath);
        string first_line;
        getline(file, first_line);
        file.close();

        int num_columns = 0;
        istringstream iss(first_line);
        string token;
        while (iss >> token) {
            num_columns++;
        }

        // Columns: Timestamp(1) + Cores(N) + RAM(1) + Airtime(1) + Drops(1) = N + 4
        int num_cores = max(1, num_columns - 4);

        // RAM is located right after the core columns
        int ram_col = num_cores + 2;

        FILE* gnuplot = popen("gnuplot", "w");
        if (!gnuplot) return;

        fprintf(gnuplot, "set terminal pngcairo size 1024,768\n");
        fprintf(gnuplot, "set output '%s'\n", output_imagepath.c_str());
        fprintf(gnuplot, "set xdata time\n");
        fprintf(gnuplot, "set timefmt '%%s'\n");
        fprintf(gnuplot, "set format x '%%H:%%M:%%S'\n");

        fprintf(gnuplot, "set ytics nomirror\n");
        fprintf(gnuplot, "set y2tics\n");
        fprintf(gnuplot, "set ylabel 'CPU Usage (%%)'\n");
        fprintf(gnuplot, "set yrange [0:100]\n");
        fprintf(gnuplot, "set y2label 'Free Memory (KB)'\n");
        fprintf(gnuplot, "set y2range [0:*]\n");
        fprintf(gnuplot, "set grid\n");
        fprintf(gnuplot, "set key outside\n");

        // Draw vertical red lines for ACM events
        int arrow_idx = 1;
        for (long long ts : acm_timestamps) {
            fprintf(gnuplot, "set arrow %d from '%lld', graph 0 to '%lld', graph 1 nohead lc rgb 'red' lw 2\n",
                    arrow_idx++, ts, ts);
        }

        // Build the plot command dynamically based on the number of cores
        string plot_cmd = "plot ";
        for (int i = 0; i < num_cores; ++i) {
            plot_cmd += "'" + data_filepath + "' using 1:" + to_string(i + 2) +
                        " with lines lw 2 title 'Core " + to_string(i) + " %' axes x1y1, ";
        }

        // Append the RAM plot
        plot_cmd += "'" + data_filepath + "' using 1:" + to_string(ram_col) +
                    " with lines lw 2 dt 2 title 'Free RAM' axes x1y2\n";

        fprintf(gnuplot, "%s", plot_cmd.c_str());
        pclose(gnuplot);
    }

    void create_graph(const RunStatus &rs, const string& source){
        const auto log_path = get_observer_folder(rs, "resource_checker")/("access_point"+SUFFIX_res+".log");
        if(source == "external") create_resource_monitor_graph(log_path);
        if(source == "internal") create_resource_pid_graph(log_path);
    }

    // ------------------------ ACM monitoring ---------------------
    vector<long long> parse_acm_log(const string& filepath) {
        vector<long long> timestamps;
        ifstream file(filepath);
        string line;

        while (getline(file, line)) {
            if (line.empty()) continue;

            istringstream iss(line);
            long long ts;
            if (iss >> ts) { timestamps.push_back(ts);}
        }
        return timestamps;
    }
    void start_acm_monitoring_remote(RunStatus &rs, const string &actor_name) {
        const auto& actor = rs.get_actor(actor_name);
        const string remote_log = "/tmp/" + actor_name + "_acm.log";
        const string local_log = get_observer_folder(rs, program_name) / (actor_name + "_acm.log");


        //TODO
        const string cmd = R"(logread -f | awk '/anti-clogging/ { "date +%s" | getline ts; close("date +%s"); print ts " " $0; fflush(); }' > )" + remote_log;

        const vector<string> ssh_command = {
            "sshpass", "-p", actor["ssh_password"],
            "ssh", "-o", "StrictHostKeyChecking=no",
            actor["ssh_user"] + "@" + actor["whitebox_ip"],
            cmd
        };

        rs.process_manager.run(actor_name + "_acm", ssh_command, get_observer_folder(rs, program_name));
        rs.process_manager.on_stop(actor_name + "_acm", [remote_log, local_log, actor]() {
            actor->conn->download_file(remote_log, local_log);
            actor->conn->exec("rm " + remote_log);
        });
    }
}
