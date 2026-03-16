#include "observer/iperf_wrapper.h"
#include "logger/error_log.h"
#include <cassert>
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include <filesystem>
#include <sciplot/Plot2D.hpp>
#include <sciplot/Figure.hpp>
#include <sciplot/Canvas.hpp>
#include "observer/observers.h"

namespace wpa3_tester::observer{
    using namespace std;
    using namespace sciplot;
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
                             const path &output_path){
        //throw not_implemented_error("GNUplot have to be used, matplot is mess");

        if (data.bandwidths.empty()) return;  //FIXME použít gnuplot ?
        Plot2D plot;
        plot.xlabel("Sample [ms]");
        plot.ylabel("Throughput [Kbit/s]");
        plot.gnuplot("set logscale y");
        plot.drawCurve(data.intervals, data.bandwidths).label(label);

        Figure fig = {{plot}};
        const Canvas canvas = {{fig}};
        canvas.save(output_path.string());
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
            log(LogLevel::ERROR, "Rendering failed: "+ e.what());
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
            //"-u", //dát do observer conifg
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