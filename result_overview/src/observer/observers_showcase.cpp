#include "observer/observers_showcase.h"
#include <algorithm>
#include <filesystem>
#include "logger/log.h"
#include "observer/graph/graph_elements.h"
#include "observer/observers.h"
#include "observer/state_log_graph.h"
#include "observer/tshark_wrapper.h"
#include "overview/html_guard.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;

static const path TEST_DATA = root_dir().parent_path() / "result_overview" / "src" / "observer" / "observers_test_data";

// Parses a pre-extracted CSV (frame_num|timestamp|size), renders a packet-size-over-time PNG.
static bool draw_csv_traffic_graph(const path &csv_path, const path &png_path, const string &title) {
    auto [times, sizes] = observer::tshark::times_packet_sizes_from_csv(csv_path);
    if (times.empty()) return false;

    const auto start_time = times.front();
    observer::transform_to_relative(times, start_time);

    const auto [min_it, max_it] = minmax_element(sizes.begin(), sizes.end());
    const double pad = max(1.0, (*max_it - *min_it) * 0.1);

    auto g = Graph();
    g.ymin = *min_it - pad;
    g.ymax = *max_it + pad;
    g.file = popen("gnuplot", "w");
    if (!g.file) return false;

    g.gpcmd("set terminal pngcairo size 1600,600 enhanced font 'Arial,10'");
    g.gpcmd("set output '" + png_path.string() + "'");
    g.gpcmd("set xlabel 'Time (s)'");
    g.gpcmd("set ylabel 'Packet size (bytes)'");
    g.gpcmd("set grid");
    g.gpcmd("set tmargin 5");
    g.gpcmd("set key outside");
    g.gpcmd(escape_tex("set title '" + title + "'"));

    G_elms elms;
    elms.push_back(make_unique<GraphXYPoints>(times, sizes, "packets", "steelblue"));
    g.add_graph_elements(elms);
    g.render();
    set_public_perms(png_path);
    return true;
}

struct ShowcaseGraph {
    string png;   // output filename in page_dir
    string title; // display title
    bool ok = false;
};

// Scan dir for *.csv, render a graph per file via times_packet_sizes_from_csv.
static vector<ShowcaseGraph> graphs_from_csv_dir(const path &csv_dir, const string &prefix,
                                                  const path &page_dir) {
    vector<ShowcaseGraph> result;
    if (!exists(csv_dir)) return result;

    vector<path> csvs;
    for (const auto &e : directory_iterator(csv_dir))
        if (e.path().extension() == ".csv") csvs.push_back(e.path());
    ranges::sort(csvs);

    for (const auto &csv : csvs) {
        string stem = csv.stem().string();
        ranges::replace(stem, ' ', '_');  // spaces -> underscores for PNG filename
        const string png   = prefix + "_" + stem + ".png";
        const string title = prefix + " — " + csv.stem().string();
        const bool ok = draw_csv_traffic_graph(csv, page_dir / png, title);
        result.push_back({png, title, ok});
    }
    return result;
}

void generate_observers_showcase(const path &output_dir, const path &) {
    const path page_dir = output_dir / "observer" / "showcase";
    create_public_dirs(page_dir);

    const auto tshark_graphs  = graphs_from_csv_dir(TEST_DATA / "tshark",  "tshark",  page_dir);
    const auto tcpdump_graphs = graphs_from_csv_dir(TEST_DATA / "tcpdump", "tcpdump", page_dir);

    // state_log graph — real state log from observers_test_data/state_log/
    const path state_log_path = TEST_DATA / "state_log" / "24:ec:99:bf:c7:cf_state.log";
    const path state_png      = page_dir / "state_log.png";
    const bool state_ok       = [&]{
        if (!exists(state_log_path)) return false;
        observer::state_log_graph::create_state_log_graph(state_log_path, state_png);
        return exists(state_png);
    }();

    HtmlGuard f(page_dir);
    if (!f) return;

    f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Observer Graphs — Showcase</title>
    <link rel="stylesheet" href="../../style.css">
</head>
<body>
    <a href="../../index.html" class="back-link">&lt;- Overview</a>
    <h1>Observer Graphs — Showcase</h1>

    <div class="card">
        <p>Visual output of the <code>*_graph</code> observer functions using real captured test data.
           Observers without a graph function (<code>dmesg</code>, <code>trace_cmd</code>,
           <code>mausezahn</code>) produce raw logs only and are not shown.</p>
    </div>

    <div class="card">
        <h2>tshark &mdash; <code>tshark_graph</code></h2>
        <p>Packet size over time from real pcap captures (mc_mitm scenario).
           X axis: relative time (s), Y axis: frame length (bytes).
           Extracted with <code>tshark -T fields -e frame.number -e frame.time -e frame.len</code>.</p>
)html";

    auto render_graphs = [&](const vector<ShowcaseGraph> &graphs) {
        for (const auto &g : graphs) {
            f << "        <h3>" << g.title << "</h3>\n";
            if (g.ok)
                f << "        <img src=\"" << g.png << "\" alt=\"" << g.title << "\" style=\"max-width:100%\">\n";
            else
                f << "        <p><em>Graph not available.</em></p>\n";
        }
        if (graphs.empty())
            f << "        <p><em>No CSV files found in test data.</em></p>\n";
    };

    render_graphs(tshark_graphs);

    f << R"html(    </div>

    <div class="card">
        <h2>tcpdump &mdash; packet graph</h2>
        <p>tcpdump-captured pcap converted to CSV with tshark, visualised via <code>times_packet_sizes_from_csv</code>.</p>
)html";

    render_graphs(tcpdump_graphs);

    f << R"html(    </div>

    <div class="card">
        <h2>state_log_graph &mdash; <code>create_state_log_graph</code></h2>
        <p>Client state transitions logged by <code>ClientState::update_state()</code> into
           <code>logger/&lt;mac&gt;_state.log</code>.
           X axis: transition index, Y axis: state name (first-appearance order).
           Call at the <em>end</em> of a test — no runtime overhead.</p>
)html";

    if (state_ok)
        f << "        <img src=\"state_log.png\" alt=\"state log staircase\" style=\"max-width:100%\">\n";
    else
        f << "        <p><em>Graph not available (gnuplot missing or state log not found).</em></p>\n";

    f << R"html(    </div>

    <div class="card">
        <h2>resource_checker &mdash; <code>generate_resource_graph</code></h2>
        <p>CPU core usage (%) and free RAM (KB) logged remotely via awk, plotted with gnuplot.</p>
        <p><em>TODO: get real data</em></p>
    </div>

    <div class="card">
        <h2>station_counter &mdash; <code>generate_station_graph</code></h2>
        <p>Connected station count sampled via <code>iw dev station dump</code>.</p>
        <p><em>TODO: get real data</em></p>
    </div>

    <div class="card">
        <h2>iperf_wrapper &mdash; <code>iperf3_graph</code></h2>
        <p>Per-interval throughput (Kbit/s) from an iperf3 client session.</p>
        <p><em>TODO: get real data</em></p>
    </div>

</body>
</html>
)html";
}

}
