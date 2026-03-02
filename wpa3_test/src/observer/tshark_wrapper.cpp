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
    namespace mp = matplot;

    constexpr string program_name = "tshark";
    void start_thark(RunStatus &run_status, const string &node_name, const string& filter) {
        vector<string> command = {"sudo", "-A"};
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
            "tshark -t ad -r " + pcap_path.string() +
                " -T fields -e frame.time"
                " -e frame.len "
                "-E separator=, > " + csv_path.string()
        };

        hw_capabilities::run_cmd(gen_cmd);
        return csv_path;
    }


    double tp_to_sec(const LogTimePoint &tp) {
        return static_cast<double>(
            chrono::duration_cast<chrono::nanoseconds>(tp.time_since_epoch()).count()) / 1e9;
    };

    pair<vector<double>, double> change_to_rel_double(
            const vector<LogTimePoint>& times,
            const double start_time) {
        vector<double> rel_times;
        rel_times.reserve(times.size());
        double max_time = 0;

        for (const LogTimePoint& tp : times) {
            const double t = tp_to_sec(tp) - start_time;
            rel_times.push_back(t);
            if (t > max_time) max_time = t;
        }
        return {rel_times, max_time};
    }

    void add_events(const vector<graph_lines> & events,
        const shared_ptr<matplot::axes_type> & ax,
        const double start_time){
        if (!events.empty()) {
            auto y_lims = ax->ylim();
            const double text_y = y_lims[1] * 0.6;

            for (const auto& event : events) {
                bool first_vline = true;

                // Convert this event's highlight_times to relative seconds
                for (const LogTimePoint& tp : event.highlight_times) {
                    const double t = tp_to_sec(tp) - start_time;

                    const auto vline = ax->plot({t, t}, {y_lims[0], y_lims[1]}, "--");
                    vline->line_style("--");
                    vline->color(event.color);
                    vline->line_width(2);

                    const auto txt = ax->text(t, text_y, event.event_des);
                    txt->font_size(10);
                    txt->color(event.color);

                    if (first_vline) {
                        vline->display_name(event.event_des);
                        first_vline = false;
                    } else {
                        vline->display_name("");
                    }
                }
            }
        }
    }

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

    string tshark_graph(const RunStatus &rs,
                              const string &actor_name,
                              const vector<graph_lines>& events)
    {
        namespace fs = filesystem;
        // get times, sizes for trafffic
        path graph_path = get_observer_folder(rs, program_name) / (actor_name + "_graph.png");
        const path csv_path = extract_pcap_to_csv(rs, actor_name);
        vector<LogTimePoint> times;
        vector<double> sizes;
        times_packet_sizes_from_csv(times, sizes, csv_path);

        if (times.empty() || sizes.empty() || times.size() != sizes.size()) throw runtime_error("Invalid traffic data");

        path output_path =  get_observer_folder(rs, program_name) / (actor_name + "_graph.png");

        FILE* gp = popen("gnuplot", "w");
        if (!gp) throw runtime_error("Failed to start gnuplot");

        auto gpcmd = [&](const string& cmd) {
            fprintf(gp, "%s\n", cmd.c_str());
        };

        gpcmd("set terminal pngcairo size 1600,900 enhanced font 'Arial,10'");
        gpcmd("set output '" + output_path.string() + "'");
        gpcmd("set grid");
        gpcmd("set xlabel 'Time (s)'");
        gpcmd("set ylabel 'Packet Size'");

        gpcmd("$traffic << EOD");
        for (size_t i = 0; i < times.size(); ++i) {
            double t = chrono::duration<double>(
                           times[i].time_since_epoch()).count();
            gpcmd(std::to_string(t) + " " + std::to_string(sizes[i]));
        }
        gpcmd("EOD");

        auto [min_it, max_it] = minmax_element(sizes.begin(), sizes.end());
        double ymin = *min_it;
        double ymax = *max_it;
        double pad = (ymax - ymin) * 0.2;
        if (pad == 0) pad = 1.0;
        ymin -= pad;
        ymax += pad;

        ostringstream yr;
        yr << "set yrange [" << ymin << ":" << ymax << "]";
        gpcmd(yr.str());

        gpcmd("$events << EOD");

        size_t global_index = 0;

        for (const auto& ev : events) {
            for (const auto& tp : ev.highlight_times) {

                double t = chrono::duration<double>(
                               tp.time_since_epoch()).count();

                double y;
                if (global_index % 2 == 0)
                    y = ymax - pad * (0.3 + (global_index % 5) * 0.05);
                else
                    y = ymin + pad * (0.3 + (global_index % 5) * 0.05);

                ostringstream oss;
                oss << fixed << setprecision(6)
                    << t << " " << y << " \""
                    << ev.event_des << "\" \""
                    << ev.color << "\"";

                gpcmd(oss.str());
                global_index++;
            }
        }

        gpcmd("EOD");

        gpcmd("set multiplot layout 1,1 title 'Network Traffic - " + actor_name + "'");

        ostringstream plotcmd;
        plotcmd
            << "plot "
            << "$traffic using 1:2 with lines lw 2 lc rgb '#1f77b4' title 'Traffic', "
            << "$events using 1:(" << ymin << "):(" << ymax << "):5 "
            << "with lines lc rgb variable dt 2 notitle, "
            << "$events using 1:2:5 with points pt 7 ps 1.5 lc rgb variable notitle, "
            << "$events using 1:2:3:5 with labels tc rgb variable offset 0.5,0.5 notitle";

        gpcmd(plotcmd.str());
        gpcmd("unset multiplot");

        fflush(gp);
        int rc = pclose(gp);
        if (rc != 0) throw runtime_error("Gnuplot failed");

        return output_path.string();
    }
}

