#include "observer/grapth/graph_elements.h"
#include "observer/grapth/graph_utils.h"

using namespace std;

namespace wpa3_tester{

    void Graph::gpcmd(const string& cmd) const{
        fprintf(file, "%s\n", cmd.c_str());
    }

    void Graph::add_XY_points(const GraphXYPoints &xy_points){
        gpcmd("$"+xy_points.label+" << EOD");
        for (size_t i = 0; i < xy_points.x_times.size(); ++i) {
            const double t = chrono::duration<double>(xy_points.x_times[i].time_since_epoch()).count();
            ostringstream line;
            line << fixed << setprecision(9) << t << " " << xy_points.y_values[i];
            gpcmd(line.str());
        }
        ostringstream part;
        part << "$" + xy_points.label << " using 1:2"
             << " with points pt 7 ps 0.7"
             << " lc rgb '" << xy_points.color << "'"
             << " title '" << xy_points.label << "'";
        plot_parts.push_back(part.str());
        gpcmd("EOD");
    }

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

            double y_center = (ymin + ymax) / 2.0;
            double step = 10 * event_block_index * (1.0 / event_size);
            double y = (event_block_index % 2 == 0)
                ? y_center - step
                : y_center + step;

            //change ymax/ymin, if needed
            int pad =  (ymax-ymin)/7;
            if(y < ymin) ymin = y - pad;
            if(y > ymax) ymax = y + pad;

            fprintf(file, "%s %f %f \"%s\"\n",
                t_str.c_str(), y, (ymax+ymin)/2, event_lines.label.c_str());
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

    void Graph::render() {
        gpcmd("set yrange ["+to_string(ymin) +":"+to_string(ymax) +"]");

        ostringstream plotcmd;
        plotcmd << "plot ";
        for (size_t i = 0; i < plot_parts.size(); ++i) {
            plotcmd << plot_parts[i];
            if (i + 1 < plot_parts.size()) plotcmd << ", ";
        }
        gpcmd(plotcmd.str());
        fflush(file);

        const int rc = pclose(file);
        file = nullptr;
        if (rc != 0) throw runtime_error("Gnuplot failed");
    }
}
