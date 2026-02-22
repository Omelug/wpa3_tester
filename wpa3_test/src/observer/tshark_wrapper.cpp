#include <filesystem>
#include "config/RunStatus.h"
#include "observer/observers.h"
#include "observer/tshark_wrapper.h"
#include <matplot/matplot.h>

#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::observer{
    using namespace std;
    using namespace filesystem;
    namespace mp = matplot;

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

    string plot_traffic_graph(const RunStatus& rs,
                              const string& actor_name,
                              const vector<LogTimePoint>& times, const vector<double>& sizes,
                              const std::vector<graph_lines>& events) {
        string graph_path = get_observer_folder(rs, program_name) / (actor_name + "_graph.png");
        if (times.empty()) return "";

        const auto tp_to_sec = [](const LogTimePoint& tp) {
            return static_cast<double>(
                chrono::duration_cast<chrono::nanoseconds>(tp.time_since_epoch()).count()) / 1e9;
        };

        const double start_time = tp_to_sec(times[0]);
        auto [rel_times, max_time] = change_to_rel_double(times, start_time);

        const auto fig = mp::figure();
        fig->quiet_mode(true);
        fig->width(1200);
        fig->height(700);

        const auto ax = fig->current_axes();
        ax->xlim({0, max_time});
        ax->ylim({1, 3000});

        vector<double> y = sizes;
        for (auto& v : y) if (v <= 0.0) v = 1e-3;

        ax->xlabel("Time [s]");
        ax->ylabel("Size [B]");
        ax->title("Traffic: " + escape_tex(actor_name));

        const auto p = ax->semilogy(rel_times, y, "ro");
        p->marker_size(4);
        p->marker_face_color({0, 0.5, 0.5});
        p->display_name("");

        ax->hold(true);

        add_events(events, ax, start_time);

        auto lgd = ax->legend();
        fig->save(graph_path);
        return graph_path;
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
                        const std::vector<graph_lines>& events) {
        path graph_path = get_observer_folder(rs, program_name) / (actor_name + "_graph.png");
        const path csv_path = extract_pcap_to_csv(rs, actor_name);

        vector<LogTimePoint> times;
        vector<double> sizes;
        times_packet_sizes_from_csv(times, sizes, csv_path);

        if (times.empty()) {
            log(LogLevel::ERROR, "No data found in pcap for", actor_name.c_str());
            return "";
        }

        return plot_traffic_graph(rs, actor_name, times, sizes, events);
    }

}

