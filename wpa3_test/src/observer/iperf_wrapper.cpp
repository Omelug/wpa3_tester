#include "observer/iperf_wrapper.h"

#include "attacks/channel_switch/channel_switch.h"
#include "logger/error_log.h"
#include <cassert>
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include <filesystem>
#include <sciplot/Plot2D.hpp>
#include <sciplot/Figure.hpp>
#include <sciplot/Canvas.hpp>
#include <sciplot/sciplot.hpp>
#include <matplot/matplot.h>

using namespace std;
using namespace sciplot;
namespace mp = matplot;

IperfData parse_iperf_log(const filesystem::path &log_path, const string &actor_tag) {
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
        } catch (...) { continue; }
    }
    return data;
}

static void render_graph(const IperfData &data,
                         const string &label,
                         const filesystem::path &output_path,
                         const PlotLibrary lib){
    if (data.bandwidths.empty()) return;

    if (lib == PlotLibrary::SCIPLOT) {
        Plot2D plot;
        plot.xlabel("Sample [ms]");
        plot.ylabel("Throughput [Kbit/s]");
        plot.gnuplot("set logscale y");
        plot.drawCurve(data.intervals, data.bandwidths).label(label);

        Figure fig = {{plot}};
        const Canvas canvas = {{fig}};
        canvas.save(output_path.string());

    } else if (lib == PlotLibrary::MATPLOT) {
        auto f = mp::figure(true);
        f->quiet_mode(true);
        auto ax = f->current_axes();

        std::vector<double> y = data.bandwidths;
        for (auto& v : y) {
            if (v <= 0.0){
                constexpr double eps = 1e-3;
                v = eps;
            }
        } //do not use for stats ! contaminated data (add epsilon ofr better visualization)

        ax->semilogy(data.intervals, y)->display_name(label);
        ax->xlabel("Sample [ms]");
        ax->ylabel("Throughput [Kbit/s]");
        ax->legend();
        //f->draw();
        f->save(output_path.string());

    }
}

void iperf3_graph(const std::filesystem::path &log_path,
                         const std::string &actor_tag,
                         const std::string &output_png,
                         const PlotLibrary lib) {

    if (!filesystem::exists(log_path)) {
        log(LogLevel::ERROR, "iperf3 log file not found: %s", log_path.string().c_str());
        return;
    }

    const IperfData data = parse_iperf_log(log_path, actor_tag);

    if (data.bandwidths.empty()) {
        log(LogLevel::WARNING, "No samples parsed for: %s", actor_tag.c_str());
        return;
    }

    const filesystem::path full_output_path = log_path.parent_path() / output_png;
    try {
        render_graph(data, actor_tag, full_output_path, lib);
        log(LogLevel::INFO, "Graph saved via %s to %s",
            (lib == PlotLibrary::SCIPLOT ? "sciplot" : "matplot++"),
            full_output_path.string().c_str());
    } catch (const exception &e) {
        log(LogLevel::ERROR, "Rendering failed: %s", e.what());
    }
}