#include "observer/station_counter.h"
#include <filesystem>
#include <string>
#include <vector>
#include "config/RunStatus.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "../../include/observer/grapth/graph_utils.h"
#include "observer/observers.h"
#include "observer/tshark_wrapper.h"

namespace wpa3_tester::observer::station_counter {
    using namespace std;
    using namespace filesystem;

    const string program_name = "station_counter";

    static void start_remote(RunStatus& rs,
                         const string& actor_name,
                         const int interval_sec,
                         const string& local_log)
    {
        const auto& actor = rs.get_actor(actor_name);
        const string iface = rs.get_actor(actor_name)["iface"];

        const string remote_log = "/tmp/" + actor_name + SUFFIX_sta + ".log";
        const string pid_file   = remote_log + ".pid";

        const string script =
            "while true; do "
            "  count=$(iw dev " + iface + " station dump 2>/dev/null"
            "          | grep -c '^Station' || echo 0); "
            "  echo \"$(date +%s) $count\" >> " + remote_log + "; "
            "  sleep " + to_string(interval_sec) + "; "
            "done";

        actor->conn->exec("sh -c '" + script + "' & echo $! > " + pid_file, false);

        actor->conn->on_disconnect([remote_log, local_log, actor, pid_file]() {
            actor->conn->exec("kill $(cat " + pid_file + "); rm " + pid_file);
            actor->conn->download_file(remote_log, local_log);
            actor->conn->exec("rm " + remote_log);
        });
    }

    static void start_local(RunStatus& rs,
                            const string& actor_name,
                            const string& iface,
                            const int interval_sec)
    {
        const string check_cmd = "iw dev " + iface + " station dump 2>&1";
        FILE* pipe = popen(check_cmd.c_str(), "r");
        if (!pipe) {
            throw runtime_error("station_counter: popen failed for iw on iface " + iface);
        }
        char buf[256] = {};
        fgets(buf, sizeof(buf), pipe);
        pclose(pipe);

        if (string(buf).find("No such device") != string::npos ||
            string(buf).find("command failed") != string::npos) {
            throw runtime_error(
                "station_counter: interface '" + iface + "' not found or not an AP interface.");
        }

        const string log_dir = get_observer_folder(rs, program_name);
        const string script =
            "while true; do "
            "  count=$(iw dev " + iface + " station dump 2>/dev/null"
            "          | grep -c '^Station' || echo 0); "
            "  echo \"$(date +%s) $count\"; "
            "  sleep " + to_string(interval_sec) + "; "
            "done";

        const vector<string> cmd = { "sh", "-c", script };

        rs.process_manager.run(
            actor_name + SUFFIX_sta,
            cmd, {},
            log_dir
        );
    }

    void start_station_monitoring(RunStatus& rs,
                                  const string& actor_name,
                                  const int interval_sec){
        const auto actor    = rs.get_actor(actor_name);
        const string local_log =
            get_observer_folder(rs, program_name) / (actor_name + SUFFIX_sta + ".log");

        const auto iface = rs.get_actor(actor_name)["iface"];
        if (actor->conn != nullptr) {
            start_remote(rs, actor_name, interval_sec, local_log);
        } else {
            start_local(rs, actor_name, iface, interval_sec);
        }
    }

     void generate_station_graph(const string& data_filepath,
                                const string& output_imagepath,
                                const std::vector<std::unique_ptr<GraphElements>>& elements)
    {
        // ymax (station count)
        double ymax = 1.0;
        {
            ifstream f(data_filepath);
            string line;
            while (getline(f, line)) {
                if (line.empty()) continue;
                istringstream iss(line);
                long long ts; double count;
                if (iss >> ts >> count) ymax = max(ymax, count);
            }
        }
        auto graph = Graph();
        graph.ymin = 0.0;
        graph.ymin = 0.0;


        graph.file = popen("gnuplot", "w");
        if (!graph.file) throw runtime_error("Failed to start gnuplot");

        auto gpcmd = [&](const string& cmd) { fprintf(graph.file, "%s\n", cmd.c_str()); };

        gpcmd("set terminal pngcairo size 1600,600 enhanced font 'Arial,10'");
        gpcmd("set output '"  + output_imagepath + "'");
        gpcmd("set datafile commentschars '#'");
        gpcmd("set xdata time");
        gpcmd("set timefmt '%s'");
        gpcmd("set format x '%M:%S'");
        gpcmd("set xtics rotate by -45");
        gpcmd("set ylabel 'Connected Stations'");
        gpcmd("set yrange [0:" + to_string(static_cast<int>(ymax) + 1) + "]");
        gpcmd("set ytics 1");
        gpcmd("set grid");
        gpcmd("set key outside");
        gpcmd("set tmargin 5");
        gpcmd("set bmargin 5");
        gpcmd(escape_tex("set title 'Station Count'"));

        graph.plot_parts.push_back(
            "'" + data_filepath + "' using 1:2"
            " with steps lw 2 lc rgb '#1f77b4' title 'Stations'");

        graph.add_graph_elements(elements);

        ostringstream plotcmd;
        plotcmd << "plot ";
        for (size_t i = 0; i < graph.plot_parts.size(); ++i) {
            plotcmd << graph.plot_parts[i];
            if (i + 1 < graph.plot_parts.size()) plotcmd << ", ";
        }
        gpcmd(plotcmd.str());
        fflush(graph.file);

        if (pclose(graph.file) != 0) throw runtime_error("Gnuplot failed for station graph");
    }

    void create_station_graph(const RunStatus& rs,
                              const string& actor_name,
                              const std::vector<std::unique_ptr<GraphElements>>& elements){
        const path log_path = get_observer_folder(rs, program_name)
                              / (actor_name + SUFFIX_sta + ".log");
        const string output  = path(log_path).replace_extension(".png").string();
        remove(output);
        generate_station_graph(log_path.string(), output, elements);
    }

}
