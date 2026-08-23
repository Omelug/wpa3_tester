#include "observer/state_log_graph.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <ranges>
#include <string>
#include <vector>
#include "config/RunStatus.h"
#include "logger/log.h"
#include "system/utils.h"

namespace wpa3_tester::observer::state_log_graph {
using namespace std;
using namespace filesystem;

struct Transition {
    string from, to;
    optional<LogTimePoint> ts;
};

static vector<Transition> parse_state_log(const path &p) {
    vector<Transition> result;
    ifstream f(p);
    for (string line; getline(f, line); ) {
        const auto colon = line.find(" : ");
        const auto arrow = line.find(" -> ");
        if (colon == string::npos || arrow == string::npos || arrow < colon) continue;
        const LogTimePoint tp = log_time_to_epoch_ns(line);
        result.push_back({
            line.substr(colon + 3, arrow - colon - 3),
            line.substr(arrow + 4),
            tp.time_since_epoch().count() != 0 ? optional{tp} : nullopt
        });
    }
    return result;
}

void create_state_log_graph(const path &state_log_path, const path &output_png) {
    const auto transitions = parse_state_log(state_log_path);
    if (transitions.empty()) {
        log(LogLevel::WARNING, "state_log_graph: empty or unparseable: {}", state_log_path.string());
        return;
    }

    // Unique states in first-appearance order (from then to)
    vector<string> states;
    auto add = [&](const string &s) {
        if (ranges::find(states, s) == states.end()) states.push_back(s);
    };
    for (const auto &[f, t, _] : transitions) { add(f); add(t); }

    auto state_idx = [&](const string &s) {
        return static_cast<int>(ranges::find(states, s) - states.begin());
    };

    const bool has_times = ranges::all_of(transitions, [](const Transition &t){ return t.ts.has_value(); });
    const LogTimePoint t0 = has_times ? *transitions.front().ts : LogTimePoint{};

    auto x_val = [&](size_t i) -> double {
        if (has_times)
            return chrono::duration_cast<chrono::duration<double>>(*transitions[i].ts - t0).count();
        return static_cast<double>(i);
    };

    FILE *gp = popen("gnuplot", "w");
    if (!gp) { log(LogLevel::ERROR, "state_log_graph: failed to open gnuplot"); return; }

    fprintf(gp, "set terminal pngcairo size 1400,500 enhanced font 'Arial,10'\n");
    fprintf(gp, "set output '%s'\n", output_png.c_str());
    fprintf(gp, "set grid\n");
    fprintf(gp, "set key outside right top\n");
    fprintf(gp, "set xlabel 'Time (s from start)'\n");
    fprintf(gp, "set yrange [-0.5:%f]\n", static_cast<double>(states.size()) - 0.5);

    const double duration = x_val(transitions.size() - 1);
    fprintf(gp, "set xrange [%f:%f]\n", -0.5, duration + 0.5);

    // Y-axis: state name labels
    fprintf(gp, "set ytics (");
    for (size_t i = 0; i < states.size(); ++i) {
        if (i > 0) fprintf(gp, ", ");
        fprintf(gp, "'%s' %zu", states[i].c_str(), i);
    }
    fprintf(gp, ")\n");

    string label = state_log_path.stem().string();
    if (label.ends_with(SUFFIX_state))
        label.resize(label.size() - SUFFIX_state.size());
    fprintf(gp, "set title 'State Transitions — %s'\n", label.c_str());

    fprintf(gp,
        "plot '-' with steps lw 2 lc rgb 'steelblue' title '%s', "
        "     '-' with points pt 7 ps 1.2 lc rgb 'steelblue' notitle\n",
        label.c_str());
    for (size_t i = 0; i < transitions.size(); ++i)
        fprintf(gp, "%f %d\n", x_val(i), state_idx(transitions[i].to));
    fprintf(gp, "e\n");
    for (size_t i = 0; i < transitions.size(); ++i)
        fprintf(gp, "%f %d\n", x_val(i), state_idx(transitions[i].to));
    fprintf(gp, "e\n");

    pclose(gp);
    set_public_perms(output_png);
}

void create_state_log_graph(const RunStatus &rs, const string &mac_str) {
    const path log_path = rs.run_folder() / "logger" / (mac_str + string(SUFFIX_state) + ".log");
    if (!exists(log_path)) {
        log(LogLevel::WARNING, "state_log_graph: not found: {}", log_path.string());
        return;
    }
    create_state_log_graph(log_path,
        log_path.parent_path() / (mac_str + string(SUFFIX_state) + ".png"));
}

}
