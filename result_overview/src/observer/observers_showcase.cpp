#include "observer/observers_showcase.h"
#include <filesystem>
#include <format>
#include "config/Actor_Config/actor_keys.h"
#include "config/RunStatus.h"
#include "logger/log.h"
#include "observer/graph/graph_elements.h"
#include "observer/iperf_wrapper.h"
#include "observer/resource_checker.h"
#include "observer/state_log_graph.h"
#include "observer/station_counter.h"
#include "observer/tshark_wrapper.h"
#include "overview/html_guard.h"
#include "system/utils.h"

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
namespace tshark = observer::tshark;

static const path TEST_DATA = OBSERVERS_TEST_DATA;

// returns png filename relative to page_dir, empty on failure
static string tshark_showcase(RunStatus &rs, const path &page_dir) {
    const string client_mac = rs.get_actor("client").get(SK::mac);

    G_elms elements;
    rs.log_events(elements, { DISCONNECT, CONNECT, TESTER_TAGS });
    rs.log_events(elements, { { "client", "CTRL-EVENT-STARTED-CHANNEL-SWITCH", "SWITCH", "blue" } });
    tshark::pcap_events(rs, elements,
            { { "attacker", "wlan.fc.type_subtype == 0x04 && wlan.sa == " + client_mac, "client PROBE", "black" }});

    const path png = tshark::tshark_graph(rs, "client", elements);
	copy_f(png , page_dir / png.filename().string() );
    return png.empty() ? "" : png.filename().string();
}

static string resource_checker_showcase(const path &page_dir) {
    const path log  = TEST_DATA / "observer" / "resource_checker" / "ap_res.log";
    const path png  = page_dir / "resource_checker.png";
    observer::resource_checker::generate_resource_graph(log, png);
    return exists(png) ? png.filename().string() : "";
}

static string station_counter_showcase(const path &page_dir) {
    const path log = TEST_DATA / "observer" / "station_counter" / "ap_sta.log";
    const path png = page_dir / "station_counter.png";
    observer::station_counter::generate_station_graph(log.string(), png.string(), {});
    return exists(png) ? png.filename().string() : "";
}

static string state_log_showcase(const path &page_dir) {
    const path log_path = TEST_DATA / "observer" / "client_state" / "24:ec:99:bf:c7:cf_state.log";
    const path png_path = page_dir / "state_log.png";
    observer::state_log_graph::create_state_log_graph(log_path, png_path);
	return exists(png_path) ? png_path.filename().string() : "";
}

void generate_observers_showcase(const path &output_dir, const path &) {
    const path page_dir = output_dir / "observer" / "showcase";
    create_public_dirs(page_dir);

    RunStatus rs;
    rs.run_folder(TEST_DATA);
    rs.load_actor_interface_mapping();

    const string tshark_png    = tshark_showcase(rs, page_dir);
    const string resource_png  = resource_checker_showcase(page_dir);
    const string station_png   = station_counter_showcase(page_dir);
    const string state_log_png = state_log_showcase(page_dir);

    auto img = [](const string &png, const string &alt) -> string {
        if(png.empty()) return "<p><em>Graph not available.</em></p>";
        return format(R"(<img src="{}" alt="{}" style="max-width:100%">)", png, alt);
    };

    HtmlGuard f(page_dir);
    f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>observer graphs showcase</title>
    <link rel="stylesheet" href="../../style.css">
</head>
<body>
    <a href="../../index.html" class="back-link"><= Overview</a>
    <h1>observer graphs - showcase</h1>

    <div class="card">
        <h2>tshark - <code>tshark_graph</code></h2>
        <p>Packet size over time with event overlays (channel_switch rogueAP scenario).
           Disconnect/connect events from actor logs, client probe requests from pcap.</p>
)html";
    f << img(tshark_png, "tshark graph");
    f << R"html(</div>

    <div class="card">
        <h2>state_log - <code>create_state_log_graph</code></h2>
        <p>Station state transitions over time (staircase plot).</p>
)html";
    f << img(state_log_png, "state log staircase");
    f << R"html(</div>

    <div class="card">
        <h2>resource_checker - <code>generate_resource_graph</code></h2>
        <p>CPU core usage (%) and free RAM (KB) logged remotely via awk (pmk_gobbler Dlink scenario).</p>
)html";
    f << img(resource_png, "resource checker graph");
    f << R"html(</div>

    <div class="card">
        <h2>station_counter - <code>generate_station_graph</code></h2>
        <p>Connected station count sampled via <code>iw dev station dump</code> (pmk_gobbler Dlink scenario).</p>
)html";
    f << img(station_png, "station counter graph");
    f << R"html(</div>
</body></html>)html";
}

}
