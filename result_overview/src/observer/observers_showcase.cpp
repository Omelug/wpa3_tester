#include "observer/observers_showcase.h"
#include <cmath>
#include <filesystem>
#include <fstream>
#include "observer/iperf_wrapper.h"
#include "observer/resource_checker.h"
#include "observer/station_counter.h"
#include "overview/html_guard.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;

static constexpr long long BASE_TS = 1700000000LL;
static constexpr int N = 40;

// Format: # comment header, then "timestamp cpu0 cpu1 mem_free_kb airtime rx_drops"
// generate_resource_graph counts columns from the 2nd line to determine num_cores
static path make_resource_data(const path &dir) {
    const path p = dir / "sample_resource.log";
    ofstream f(p);
    f << "# timestamp cpu0 cpu1 mem_free airtime rx_drops\n";
    for (int i = 0; i < N; ++i) {
        const long long ts  = BASE_TS + i;
        const int cpu0      = 20 + (int)(28 * sin(i * 0.4));
        const int cpu1      = 10 + (int)(18 * cos(i * 0.3 + 1.0));
        const long long mem = 8'000'000LL - i * 40'000LL + (long long)(300'000 * sin(i * 0.5));
        const int airtime   = 5 + i % 15;
        const int drops     = (i % 11 == 0) ? 4 : 0;
        f << ts << ' ' << cpu0 << ' ' << cpu1 << ' ' << mem << ' ' << airtime << ' ' << drops << '\n';
    }
    return p;
}

// Format: "timestamp station_count"
static path make_station_data(const path &dir) {
    const path p = dir / "sample_station.log";
    ofstream f(p);
    for (int i = 0; i < N; ++i) {
        const long long ts = BASE_TS + i;
        int count = 3;
        if (i >= 8  && i < 22) count = 5;
        if (i >= 22 && i < 30) count = 4;
        f << ts << ' ' << count << '\n';
    }
    return p;
}

// iperf3_graph parser requires lines matching "[tag] ... <number> Kbits/sec"
static path make_iperf_data(const path &dir) {
    const path p = dir / "sample_iperf.log";
    ofstream f(p);
    for (int i = 0; i < N; ++i) {
        double bw = 8500.0 + 1800.0 * sin(i * 0.35);
        if (i % 8 == 0) bw *= 0.25;  // periodic dip
        if (bw < 80) bw = 80;
        f << "[client] " << i << ".00-" << (i + 1) << ".00 sec  " << (int)bw << " Kbits/sec\n";
    }
    return p;
}

void generate_observers_showcase(const path &output_dir, const path &) {
    const path page_dir = output_dir / "observer" / "showcase";
    create_public_dirs(page_dir);

    const path res_png = page_dir / "resource.png";
    const path sta_png = page_dir / "station.png";
    const path ipr_png = page_dir / "iperf.png";

    observer::resource_checker::generate_resource_graph(make_resource_data(page_dir), res_png);
    observer::station_counter::generate_station_graph(
        make_station_data(page_dir).string(), sta_png.string(), {});
    // ponytail: iperf3_graph writes to log_path.parent() / output_png (filename only)
    observer::iperf3_graph(make_iperf_data(page_dir), "client", ipr_png.filename().string());

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
        <p>Observers without a graph function (<code>tshark</code>, <code>dmesg</code>, <code>trace_cmd</code>,
           <code>mausezahn</code>) are not shown here — they produce raw logs only.</p>
    </div>

    <div class="card">
        <h2>Resource Monitor &mdash; <code>resource_checker::generate_resource_graph</code></h2>
        <p>CPU core usage (%) on left axis; free RAM (KB) on right axis.
           Logged remotely via an awk script, rendered with gnuplot.</p>
        <img src="resource.png" alt="Resource monitor graph" style="max-width:100%">
    </div>

    <div class="card">
        <h2>Station Counter &mdash; <code>station_counter::generate_station_graph</code></h2>
        <p>Number of associated stations on the AP interface, sampled every second via <code>iw dev station dump</code>.</p>
        <img src="station.png" alt="Station count graph" style="max-width:100%">
    </div>

    <div class="card">
        <h2>Iperf3 Throughput &mdash; <code>iperf_wrapper::iperf3_graph</code></h2>
        <p>Per-interval bandwidth (Kbit/s) from an iperf3 client session</p>
        <img src="iperf.png" alt="Iperf3 throughput graph" style="max-width:100%">
    </div>

</body>
</html>
)html";
}

}
