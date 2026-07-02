#include "observer/graph/graph_elements.h"

#include "logger/error_log.h"
#include "observer/graph/graph_utils.h"
#include "system/utils.h"

using namespace std;

namespace wpa3_tester{
void Graph::gpcmd(const string &cmd) const{
	fprintf(file, "%s\n", cmd.c_str());
}

void Graph::add_XY_points(const GraphXYPoints &xy_points){
	gpcmd("$" + xy_points.label + " << EOD");
	for(size_t i = 0; i < xy_points.x_times.size(); ++i){
		const double t = chrono::duration<double>(xy_points.x_times[i].time_since_epoch()).count();
		ostringstream line;
		line << fixed << setprecision(9) << t << " " << xy_points.y_values[i];
		gpcmd(line.str());
	}
	ostringstream part;
	part << "$" + xy_points.label << " using 1:2" << " with points pt 7 ps 0.7" << " lc rgb '" << xy_points.color << "'"
			<< " title '" << xy_points.label << "'";
	plot_parts.push_back(part.str());
	gpcmd("EOD");
}

void Graph::add_event_lines(EventLines &event_lines, size_t &event_block_index, size_t label_slot,
							size_t num_label_slots, size_t &label_index
){
	if(event_lines.event_times.empty()) return;

	const string block_name = "$ev" + to_string(event_block_index++);
	gpcmd(block_name + " << EOD");

	const double y_center = (ymin + ymax) / 2.0;
	const double step = 10.0 * static_cast<double>(label_slot) * (1.0 / static_cast<double>(num_label_slots));
	const double y = (label_slot % 2 == 0) ? y_center - step : y_center + step;

	for(const auto &tp: event_lines.event_times){
		string t_str;
		if(axis == TimeAxis::RELATIVE){
			double t = chrono::duration<double>(tp - start_time).count();
			ostringstream s;
			s << fixed << setprecision(6) << t;
			t_str = s.str();
		} else{
			t_str = to_string(chrono::system_clock::to_time_t(tp));
		}

		//change ymax/ymin, if needed
		int pad = static_cast<int>(ymax - ymin) / 7;
		if(y < ymin) ymin = y - pad;
		if(y > ymax) ymax = y + pad;

		fprintf(file, "%s %f %f \"%s\"\n", t_str.c_str(), y, (ymax + ymin) / 2, event_lines.label.c_str());
	}
	gpcmd("EOD");

	ostringstream part;
	part << block_name << " using 1:2:(0):($3-$2) with vectors nohead" << " lc rgb '" << event_lines.color <<
			"' dt 2 notitle, " << block_name << " using 1:2 with points pt 7 ps 1.2" << " lc rgb '" << event_lines.color
			<< "' notitle, " << block_name << " using 1:2:4 with labels tc rgb '" << event_lines.color << "' " << (
				label_index % 2 == 0 ? "offset 0,1" : "offset 0,-1") << " rotate by 45 notitle";

	plot_parts.push_back(part.str());
	label_index++;
}

template<typename Enum>
void Graph::add_stairs(const GraphStairs<Enum> &stairs){
	if(stairs.steps.empty()) return;

	gpcmd("$" + stairs.label + " << EOD");

	auto it = stairs.steps.begin();
	while(it != stairs.steps.end()){
		const double t_start = chrono::duration<double>(it->first.time_since_epoch()).count();
		const double y = stairs.y_pos(it->second);

		auto n = next(it);
		const double t_end = (n != stairs.steps.end())
							? chrono::duration<double>(n->first.time_since_epoch()).count()
							: t_start + 1.0; // extend last step by 1s

		// Two points per step — horizontal hold
		ostringstream a, b;
		a << fixed << setprecision(9) << t_start << " " << y;
		b << fixed << setprecision(9) << t_end << " " << y;
		gpcmd(a.str());
		gpcmd(b.str());

		it = n;
	}
	gpcmd("EOD");

	// Y axis tic labels from enum_labels
	ostringstream tics;
	const string ytics_cmd = (stairs.axis == YAxis::Y2) ? "set y2tics" : "set ytics";
	tics << ytics_cmd << " (";
	for(size_t i = 0; i < stairs.enum_labels.size(); ++i){
		if(i > 0) tics << ", ";
		tics << "'" << stairs.enum_labels[i].second << "' " << i;
	}
	tics << ")";
	gpcmd(tics.str());

	// Y range with margin
	const string yrange_cmd = (stairs.axis == YAxis::Y2) ? "set y2range" : "set yrange";
	ostringstream yrange;
	yrange << yrange_cmd << " [" << fixed << setprecision(2) << stairs.y_min() << ":" << stairs.y_max() << "]";
	gpcmd(yrange.str());

	// Plot part
	ostringstream part;
	part << "$" << stairs.label << " using 1:2" << " with lines lw 2" << " lc rgb '" << stairs.color << "'" << (
		stairs.axis == YAxis::Y2 ? " axes x1y2" : " axes x1y1") << " title '" << stairs.label << "'";
	plot_parts.push_back(part.str());
}

void Graph::render(){
	gpcmd("set yrange [" + to_string(ymin) + ":" + to_string(ymax) + "]");

	gpcmd("plot " + join(plot_parts, ", "));
	fflush(file);

	const int rc = pclose(file);
	file = nullptr;
	if(rc != 0) throw run_err("Gnuplot failed");
}
}