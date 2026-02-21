#include <filesystem>
#include "config/RunStatus.h"
#include "observer/observers.h"
#include <matplot/matplot.h>

#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::observer{
    using namespace std;
    using namespace filesystem;
    namespace mp = matplot;

    constexpr string program_name = "tshark";
    void start_thark(RunStatus &run_status, const string &node_name) {
        vector<string> command = {"sudo"};
        add_nets(run_status,command, node_name);

        string pcap_path = get_observer_folder(run_status, program_name) / (node_name + "_capture.pcap");
        command.insert(command.end(), {
            program_name, "-i", run_status.get_actor(node_name)["iface"],
            "-w", pcap_path,
            "-f", "udp port 5201", //TODO hardcoded
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

    struct graph_lines{
        vector<LogTimePoint>& highlight_times;
        string& event_des;
    };

    string plot_traffic_graph(const RunStatus& rs,
            const string& actor_name,
            const vector<LogTimePoint>& times, const vector<double>& sizes,
            const vector<LogTimePoint>& highlight_times,
            const string& event_desc) {
        string graph_path = get_observer_folder(rs, program_name) / (actor_name + "_graph.png");
        if (times.empty()) return "";

        const auto tp_to_sec = [](const LogTimePoint& tp) {
            return static_cast<double>(
                chrono::duration_cast<chrono::nanoseconds>(tp.time_since_epoch()).count()) / 1e9;
        };

        const double start_time = tp_to_sec(times[0]);
        double max_time = 0;

        vector<double> rel_times;
        rel_times.reserve(times.size());
        for (const LogTimePoint& tp : times) {
            const double t = tp_to_sec(tp) - start_time;
            rel_times.push_back(t);
            if (t > max_time) max_time = t;
        }

        // convert LogTimePoint highlights to seconds relative to start_time
        vector<double> highlight_secs;
        highlight_secs.reserve(highlight_times.size());
        for (const LogTimePoint& tp : highlight_times) {
            const double t = tp_to_sec(tp) - start_time;
            highlight_secs.push_back(t);
            if (t > max_time) max_time = t;
        }

        const auto f = mp::figure();
        f->quiet_mode(true);
        f->width(1200);
        f->height(700);

        const auto ax = f->current_axes();
        ax->xlim({0, max_time * 1});
        ax->ylim({1, 3000});

        vector<double> y = sizes;
        for (auto& v : y) if (v <= 0.0) v = 1e-3;

        ax->xlabel("Time [s]");
        ax->ylabel("Size [B]");
        ax->title("Traffic: " + escape_tex(actor_name));

        auto p = ax->semilogy(rel_times, y, "ro");
        p->marker_size(4);
        p->marker_face_color({0, 0.5, 0.5});
        p->display_name("");

        ax->hold(true);
        if (!highlight_secs.empty()) {
            auto y_lims = ax->ylim();
            bool first_vline = true;
            const double text_y = y_lims[1] * 0.6;

            for (double t : highlight_secs) {
                const auto vline = ax->plot({t, t}, {y_lims[0], y_lims[1]}, "--b");
                vline->line_style("--");
                vline->color("blue");
                vline->line_width(2);
                const auto txt = ax->text(t, text_y, event_desc);
                txt->font_size(10);
                txt->color("blue");

                if (first_vline) {
                    vline->display_name(event_desc);
                    first_vline = false;
                } else {
                    vline->display_name("");
                }
            }
        }
        auto lgd = ax->legend();

        f->save(graph_path);
        return graph_path;
    }

    string tshark_graph(const RunStatus &rs,
        const string &actor_name,
        const vector<LogTimePoint> &highlight_times,
        const string& event_desc) {
        string pcap_path = get_observer_folder(rs, program_name) / (actor_name + "_capture.pcap");
        path csv_path = extract_pcap_to_csv(rs, "client");
        string graph_path = get_observer_folder(rs, program_name) / (actor_name + "_graph.png");

        vector<LogTimePoint> times;
        vector<double> sizes;
        ifstream file(csv_path);
        string line;

        // epoch_time,size
        while (getline(file, line)) {
            stringstream ss(line);
            string t_str, s_str;
            if (getline(ss, t_str, ',') && getline(ss, s_str, ',')) {
                try {
                    const LogTimePoint tp = log_time_to_epoch_ns(t_str);
                    if (tp.time_since_epoch().count() == 0) continue;
                    times.push_back(tp);
                    sizes.push_back(stod(s_str));
                } catch (...) {
                    continue;
                }
            }
        }

        if (times.empty()) {
            cerr << "No data found in pcap for " << actor_name << endl;
            return "";
        }

        return plot_traffic_graph(rs, actor_name, times, sizes, highlight_times, event_desc);
    }

}

