#include "observer/iperf_wrapper.h"
#include "logger/error_log.h"
#include <cassert>
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include <filesystem>
#include "observer/observers.h"

namespace wpa3_tester::observer{
    using namespace std;
    using namespace filesystem;

    IperfData parse_iperf_log(const path &log_path, const string &actor_tag) {
        IperfData data;
        ifstream ifs(log_path);
        if (!ifs.is_open()) return data;

        string line;
        while (getline(ifs, line)) {
            if (line.find("[" + actor_tag + "]") == string::npos) continue;
            if (line.find("[cmd]") != string::npos) continue;
            if (line.find("- - - - - - - - - - -") != string::npos) break;
            const auto pos_rate = line.find("Kbits/sec");
            if (pos_rate == string::npos) continue;

            size_t end = pos_rate;
            while (end > 0 && isspace(line[end - 1])) --end;
            size_t start = end;
            while (start > 0 && (isdigit(line[start - 1]) || line[start - 1] == '.')) --start;

            try {
                double bw = stod(line.substr(start, end - start));
                data.bandwidths.push_back(bw);
                data.intervals.push_back(static_cast<double>(data.bandwidths.size()));
            } catch (...) {}
        }
        return data;
    }

    static void render_graph(const IperfData &data,
                             const string &label,
                             const path &output_path) {
        if (data.bandwidths.empty() || data.intervals.empty()) return;

        FILE* gp = popen("gnuplot", "w");
        if (!gp) {throw runtime_error("Could not open pipe to gnuplot. Is it installed?");}

        string ext = output_path.extension().string();
        if (ext == ".png") {fprintf(gp, "set terminal pngcairo size 800,600\n");
        } else if (ext == ".svg") {fprintf(gp, "set terminal svg size 800,600\n");
        } else {
            fprintf(gp, "set terminal pdf\n");
        }

        fprintf(gp, "set output '%s'\n", output_path.c_str());
        fprintf(gp, "set title 'Iperf Throughput: %s'\n", label.c_str());
        fprintf(gp, "set xlabel 'Sample [ms]'\n");
        fprintf(gp, "set ylabel 'Throughput [Kbit/s]'\n");
        fprintf(gp, "set logscale y\n");
        fprintf(gp, "set grid\n");

        fprintf(gp, "plot '-' with lines lw 2 title '%s'\n", label.c_str());

        for (size_t i = 0; i < data.bandwidths.size(); ++i) {
            fprintf(gp, "%f %f\n", data.intervals[i], data.bandwidths[i]);
        }

        fprintf(gp, "e\n");
        pclose(gp);
    }

    void iperf3_graph(const path &log_path,
                             const string &actor_tag,
                             const string &output_png) {

        if (!exists(log_path)){throw config_err("iperf3 log file not found: "+log_path.string());}

        const IperfData data = parse_iperf_log(log_path, actor_tag);
        if (data.bandwidths.empty()) {log(LogLevel::WARNING, "No samples parsed for: "+actor_tag);return;}

        const path full_output_path = log_path.parent_path() / output_png;
        try {
            render_graph(data, actor_tag, full_output_path);
            log(LogLevel::INFO, "Graph saved via "+full_output_path.string());
        } catch (const exception &e) {
            log(LogLevel::ERROR, "Rendering failed: "+ string(e.what()));
        }
    }

    constexpr string program_name = "iperf3";
    void start_iperf3(RunStatus& run_status, const string &actor_name, const string &src_name, const string &dst_name){
        vector<string> command = {"sudo"};
        add_nets(run_status,command, src_name);
        command.insert(command.end(), {
            "stdbuf", "-oL", "-eL",  // disable buffering for immediate output
            program_name,
            "-B", run_status.config.at("actors").at(src_name).at("ip_addr"),
            "-c", run_status.config.at("actors").at(dst_name).at("ip_addr"),
            //"-u", //dát do observer config
            "-b", "10M",
            "-t", "0" // infinity
        });
        run_status.process_manager.run(actor_name, command, get_observer_folder(run_status, program_name));
    }

    void start_iperf3_server(RunStatus& run_status, const string &actor_name, const string &server_name){
        vector<string> command = {"sudo"};
        add_nets(run_status, command, server_name);
        command.insert(command.end(), {
            "stdbuf", "-oL", "-eL",  // disable buffering for immediate output
            program_name,
            "-s",                // server
            "-p", "5201",        // port
            //"--one-off"
        });

        run_status.process_manager.run(actor_name, command, get_observer_folder(run_status, actor_name));
    }
}