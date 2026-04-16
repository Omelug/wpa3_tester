#include "observer/grapth/graph_elements.h"

#include "observer/grapth/graph_utils.h"

using namespace std;

namespace wpa3_tester{

    void Graph::add_elements(EventLines &event_lines, size_t &event_block_index, size_t event_size, size_t &label_index){
        if (event_lines.event_times.empty()) return;

        const string block_name = "$ev" + to_string(event_block_index++);
        fprintf(file, "%s << EOD\n", block_name.c_str());

        for (const auto& tp : event_lines.event_times) {
            string t_str;
            if (axis == TimeAxis::RELATIVE) {
                double t = chrono::duration<double>(tp - start_time).count();
                ostringstream s;
                s << fixed << setprecision(6) << t;
                t_str = s.str();
            } else {
                t_str = to_string(chrono::system_clock::to_time_t(tp));
            }
            double step = event_block_index * ( ymax / event_size);
            double y = (event_block_index % 2 == 0) ? step : -step;

            fprintf(file, "%s %f %f \"%s\"\n",
                t_str.c_str(), y, ymax/2, "");
        }
        fprintf(file, "EOD\n");

        ostringstream part;
        part
            << block_name << " using 1:2:(0):($3-$2) with vectors nohead"
            << " lc rgb '" << event_lines.color << "' dt 2 notitle, "
            << block_name << " using 1:2 with points pt 7 ps 1.2"
            << " lc rgb '" << event_lines.color << "' notitle, "
            << block_name << " using 1:2:4 with labels tc rgb '" << event_lines.color << "' "
            << (label_index % 2 == 0 ? "offset 0,1" : "offset 0,-1")
            << " rotate by 45 notitle";

        plot_parts.push_back(part.str());
        label_index++;
    }
}
