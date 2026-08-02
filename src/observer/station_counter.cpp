#include "observer/station_counter.h"
#include "config/RunStatus.h"
#include "config/Observer_config.h"
#include "observer/graph/graph_elements.h"
#include "observer/graph/graph_utils.h"
#include "system/utils.h"
#include "logger/logger.h"

#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace wpa3_tester::observer {

using namespace std;
using namespace filesystem;

void StationCounter::start(RunStatus &rs) const {
    const auto &log_folder = rs.run_folder() / "logs";
    if (!exists(log_folder)) {
        throw run_err("Log folder does not exist: {}", log_folder.string());
    }

    map<string, vector<LogTimePoint>> station_times;
    for (const auto &entry : directory_iterator(log_folder)) {
        if (entry.is_directory()) {
            const auto &log_file = entry.path() / "log.txt";
            if (exists(log_file)) {
                ifstream file(log_file);
                string line;
                while (getline(file, line)) {
                    if (line.find("STA:") != string::npos) {
                        const auto time = parse_log_time(line);
                        const auto mac = line.substr(line.find("STA:") + 4, 17);
                        station_times[mac].push_back(time);
                    }
                }
            }
        }
    }

    vector<unique_ptr<GraphElements>> elements;
    for (const auto &[mac, times] : station_times) {
        vector<LogTimePoint> x_times;
        vector<double> y_values;
        for (size_t i = 0; i < times.size(); ++i) {
            x_times.push_back(times[i]);
            y_values.push_back(i + 1);
        }
        elements.push_back(make_unique<GraphXYPoints>(x_times, y_values, mac));
    }

    add_graph_elements(move(elements));
}

} // namespace wpa3_tester::observer
