#include "observer/state_log_graph.h"
#include <algorithm>
#include <ctime>
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
    optional<time_t> ts;  // nullopt when line has no timestamp prefix
};

// Tries to parse "YYYY-MM-DD HH:MM:SS" from the start of the line.
static optional<time_t> try_parse_ts(const string &line) {
    struct tm t = {};
    const char *end = strptime(line.c_str(), "%Y-%m-%d %H:%M:%S", &t);
    if (end == nullptr || *end != ' ') return nullopt;
    return mktime(&t);
}

static vector<Transition> parse_state_log(const path &p) {
    vector<Transition> result;
    ifstream f(p);
    for (string line; getline(f, line); ) {
        const auto colon = line.find(" : ");
        const auto arrow = line.find(" -> ");
        if (colon == string::npos || arrow == string::npos || arrow < colon) continue;
        result.push_back({
            line.substr(colon + 3, arrow - colon - 3),
            line.substr(arrow + 4),
            try_parse_ts(line)
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
        return (int)(ranges::find(states, s) - states.begin());
    };

    // Use real timestamps when all transitions have them, otherwise fall back to index.
    const bool has_times = ranges::all_of(transitions, [](const Transition &t){ return t.ts.has_value(); });
    const time_t t0 = has_times ? *transitions.front().ts : 0;

    auto x_val = [&](size_t i) -> double {
        if (has_times) return static_cast<double>(*transitions[i].ts - t0);
        return static_cast<double>(i);
    };

    FILE *gp = popen("gnuplot", "w");
    if (!gp) { log(LogLevel::ERROR, "state_log_graph: failed to open gnuplot"); return; }

    fprintf(gp, "set terminal pngcairo size 1400,500 enhanced font 'Arial,10'\n");
    fprintf(gp, "set output '%s'\n", output_png.c_str());
    fprintf(gp, "set grid\n");
    fprintf(gp, "set key outside right top\n");
    fprintf(gp, "set xlabel '%s'\n", has_times ? "Time (s from start)" : "Transition #");
    fprintf(gp, "set yrange [-0.5:%f]\n", (double)states.size() - 0.5);

    if (has_times) {
        const double duration = x_val(transitions.size() - 1);
        fprintf(gp, "set xrange [%f:%f]\n", -0.5, duration + 0.5);
    } else {
        fprintf(gp, "set xrange [-0.5:%f]\n", (double)transitions.size() - 0.5);
        fprintf(gp, "set xtics 1\n");
    }

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
