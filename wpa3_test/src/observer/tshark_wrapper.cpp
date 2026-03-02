#include <filesystem>
#include "config/RunStatus.h"
#include "observer/observers.h"
#include "observer/tshark_wrapper.h"
#include <matplot/matplot.h>
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>

#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::observer{
    using namespace std;
    using namespace filesystem;

    constexpr string program_name = "tshark";
    void start_thark(RunStatus &run_status, const string &node_name, const string& filter) {
        vector<string> command = {"sudo"};
        add_nets(run_status,command, node_name);

        string pcap_path = get_observer_folder(run_status, program_name) / (node_name + "_capture.pcap");
        command.insert(command.end(), {
            program_name, "-i", run_status.get_actor(node_name)["iface"],
            "-w", pcap_path,
            "-f", filter,
        });

        run_status.process_manager.run(node_name + "_cap", command, get_observer_folder(run_status, program_name));
    }

    path extract_pcap_to_csv(const RunStatus& rs, const string& actor_name) {
        const path pcap_path = get_observer_folder(rs, program_name) / (actor_name + "_capture.pcap");
        const path csv_path = get_observer_folder(rs, program_name) / (actor_name + ".csv");

        const vector<string> gen_cmd = {
            "sh", "-c",
            "tshark -l -t ad -r '" + pcap_path.string() +
            "' -T fields -e frame.time -e frame.len -E separator=, > '" +
            csv_path.string() + "'"
        };

        hw_capabilities::run_cmd(gen_cmd);
        return csv_path;
    };

    void times_packet_sizes_from_csv(vector<LogTimePoint> & times, vector<double> & sizes, path csv_path){
        ifstream file(csv_path.string());
        string line;

        // csv lines are in format epoch_time,size
        while (getline(file, line)) {
            stringstream ss(line);
            string t_str, s_str;
            if (getline(ss, t_str, ',') && getline(ss, s_str, ',')) {
                try {
                    const LogTimePoint tp = log_time_to_epoch_ns(t_str);
                    if (tp.time_since_epoch().count() == 0) continue;
                    times.push_back(tp);
                    sizes.push_back(stod(s_str));
                } catch (...) {}
            }
        }
    }
    void transform_to_relative(std::vector<LogTimePoint>& times, const LogTimePoint start_time){
        if (times.empty()) return;
        const LogTimePoint t0 = start_time;
        for (auto& t : times) {
            auto rel = t - t0;
            t = LogTimePoint(std::chrono::duration_cast<std::chrono::nanoseconds>(rel));
        }
    }

    LogTimePoint get_pcap_start_time(const string& pcap_path) {
        const vector<string> get_start_cmd = {
            "tshark","-t","ad", "-r", pcap_path,
            "-T", "fields", "-e", "frame.time", "-c", "1"
        };

        string start_str = hw_capabilities::run_cmd_output(get_start_cmd);
        start_str.erase(0, start_str.find_first_not_of(" \n\r\t"));
        start_str.erase(start_str.find_last_not_of(" \n\r\t") + 1);

        if (start_str.empty()) {
            throw runtime_error("Failed to get ISO start time from PCAP: " + pcap_path);
        }
        return log_time_to_epoch_ns(start_str);
    }

    string tshark_graph(const RunStatus &rs,
                        const string &actor_name,
                        vector<graph_lines>& events){
        path folder = get_observer_folder(rs, program_name);
        create_directories(folder);

        path output_path = folder / (actor_name + "_graph.png");
        const path csv_path = extract_pcap_to_csv(rs, actor_name);

        vector<LogTimePoint> times;
        vector<double> sizes;
        times_packet_sizes_from_csv(times, sizes, csv_path);
        const path pcap_path = get_observer_folder(rs, program_name) / (actor_name + "_capture.pcap");
        auto start_time = get_pcap_start_time(pcap_path);
        transform_to_relative(times, start_time);
        if (times.empty() || sizes.empty() || times.size() != sizes.size())
            throw runtime_error("Invalid traffic data");

        FILE* gp = popen("gnuplot", "w");
        if (!gp) throw runtime_error("Failed to start gnuplot");

        auto gpcmd = [&](const string& cmd) { fprintf(gp, "%s\n", cmd.c_str());};

        gpcmd("set terminal pngcairo size 1600,900 enhanced font 'Arial,10'");
        gpcmd("set output '" + output_path.string() + "'");
        gpcmd("set grid");
        gpcmd("set xlabel 'Time (s)'");
        gpcmd("set ylabel 'Packet Size'");

        auto [min_it, max_it] = minmax_element(sizes.begin(), sizes.end());
        double ymin = *min_it;
        double ymax = *max_it;
        double y_center = (ymin + ymax) / 2.0;
        double pad = (ymax - ymin) * 0.5;
        if (pad == 0) pad = 1.0;
        ymin -= pad;
        ymax += pad;

        {
            ostringstream yr;
            gpcmd("set tmargin 5");
            gpcmd("set bmargin 5");
            gpcmd("set yrange [" + std::to_string(ymin - pad) + ":" + std::to_string(ymax + pad) + "]");
            gpcmd(yr.str());
        }

        // traffic
        gpcmd("$traffic << EOD");
        for (size_t i = 0; i < times.size(); ++i) {
            double t = chrono::duration<double>(times[i].time_since_epoch()).count();
            ostringstream line;
            line << fixed << setprecision(9) << t << " " << sizes[i];
            gpcmd(line.str());
        }
        gpcmd("EOD");

        // events
        vector<string> plot_parts;
        plot_parts.push_back("$traffic using 1:2 with points pt 7 ps 0.7 lc rgb '#1f77b4' title 'Traffic'");

        size_t event_block_index = 0;
        size_t label_index = 0;

        for (auto& ev : events) {
            if (ev.highlight_times.empty()) continue;
            string block_name = "$ev" + std::to_string(event_block_index++);
            gpcmd(block_name + " << EOD");
            for (const auto& tp : ev.highlight_times) {

                //transform
                auto rel_dur = tp - start_time;
                double t = chrono::duration<double>(rel_dur).count();

                double y = (event_block_index % 2 == 0) ?
                    ymax - (ymax-y_center)*event_block_index*(1/static_cast<double>(events.size())):
                    ymin + (y_center-ymin)*event_block_index*(1/static_cast<double>(events.size()));

                ostringstream row;
                row << fixed << setprecision(6)
                    << t << " "          // time
                    << y << " "          // label position
                    << y_center << " "
                    << "\"" << ev.event_des << "\"";
                gpcmd(row.str());
                label_index++;
            }
            gpcmd("EOD");

            ostringstream part;
            part
                // line from event point to y center
                // using x : y : (0) : (y_target - y)
                << block_name << " using 1:2:(0):($3-$2) with vectors nohead lc rgb '" << ev.color << "' dt 2 notitle, "
                // event point
                << block_name << " using 1:2 with points pt 7 ps 1.2 lc rgb '" << ev.color << "' notitle, "
                // event
                << block_name << " using 1:2:4 with labels tc rgb '" << ev.color << "' "
                << (label_index % 2 == 0 ? "offset 0,1" : "offset 0,-1") << " rotate by 45 notitle";

            plot_parts.push_back(part.str());
        }
        gpcmd(escape_tex("set title 'Network Traffic - " + actor_name + "'"));

        //plot
        ostringstream plotcmd;
        plotcmd << "plot ";
        for (size_t i = 0; i < plot_parts.size(); ++i) {
            plotcmd << plot_parts[i];
            if (i + 1 < plot_parts.size()) plotcmd << ", ";
        }
        gpcmd(plotcmd.str());
        fflush(gp);

        int rc = pclose(gp);
        if (rc != 0) throw runtime_error("Gnuplot failed");
        return output_path.string();
    }
}

