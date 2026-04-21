#include <filesystem>
#include "config/RunStatus.h"
#include "observer/observers.h"
#include "observer/tshark_wrapper.h"
#include <cstdio>
#include <sstream>
#include <stdexcept>
#include <algorithm>

#include "logger/log.h"
#include "observer/grapth/graph_utils.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::observer::tshark{
    using namespace std;
    using namespace filesystem;

    constexpr string program_name = "tshark";

    //helper functino for join or filters
    string or_filter(const vector<string> &mac_filters){
        if (mac_filters.empty()) return "";
        ostringstream oss;
        oss << "(";
        for (size_t i = 0; i < mac_filters.size(); ++i) {
            oss << mac_filters[i];
            if (i < mac_filters.size() - 1) { oss << " or "; }
        }
        oss << ")";
        return oss.str();
    }

    string masked_mac_filter_5(const RunStatus &rs) {
        vector<string> mac_filters;

        for (const auto &actor : rs.actors | views::values) {
            string clean_mac = actor["mac"];
            if (clean_mac.length() < 10) continue;
            erase(clean_mac, ':');
            string pre = clean_mac.substr(0, 10);

            // addr1 (receiver)
            string addr1 = "(link[4:4] == 0x"+pre.substr(0, 8) +
                           " and link[8:1] == 0x"+pre.substr(8, 2)+")";

            // addr2 (transceiver)
            string addr2 = "(link[10:4] == 0x"+pre.substr(0, 8) +
                           " and link[14:1] == 0x"+pre.substr(8, 2)+")";

            mac_filters.push_back("("+addr1+" or "+addr2+")");

            /*erase(clean_mac, ':');
            string prefix = actor["mac"].substr(0, 14); // "AA:BB:CC:DD:EE"
            mac_filters.push_back("wlan host "+prefix+":00/40");

            if (clean_mac.length() == 12) {
                string prefix = clean_mac.substr(0, 10);

                // BPF offset for 802.11:
                // link[10:4] first 4 bytes SA (Source Address)
                // link[14:1] 5. byte SA
                //string f = "wlan host "+clean_mac;
                string f = "(link[10:4] == 0x"+prefix.substr(0, 8) +
                           " and link[14:1] == 0x"+prefix.substr(8, 2)+")";
                mac_filters.push_back(f);
            }*/
        }
        return or_filter(mac_filters);
    }

    // include broadcast
    string all_actors_mac_filter(const RunStatus &rs, bool broadcast = false) {
        vector<string> mac_filters;

        for (const auto &actor: rs.actors | views::values) {
            mac_filters.push_back("ether host "+actor["mac"]);
        }
        if(broadcast) mac_filters.push_back("ether host ff:ff:ff:ff:ff:ff");
        return or_filter(mac_filters);
    }
    
    void start_tshark(RunStatus &rs, const string &node_name, const string& filter) {
        vector<string> command = {};
        add_nets(rs,command, node_name);

        string pcap_path = get_observer_folder(rs, program_name) / (node_name+"_capture.pcap");
        const optional<string>iface = rs.get_actor(node_name)->str_con["sniff_iface"];
        string iface_str;
        if(iface == nullopt){
            iface_str = rs.get_actor(node_name)["iface"];
        }else {
            iface_str = iface.value();
        }

        command.insert(command.end(), {
            program_name, "-i", iface_str,
            "-w", pcap_path,
        });
        if (!filter.empty()){
            command.emplace_back("-f");
            if(filter == "special_filter:actors"){
                command.push_back(all_actors_mac_filter(rs, false));
            }else if(filter == "special_filter:actors_with_broadcast"){
                command.push_back(all_actors_mac_filter(rs, true));
            } else if(filter == "special_filter:actors_5_bytes"){
                command.push_back(masked_mac_filter_5(rs));
            }else{
                command.push_back(filter);
            }
        }
        const auto tshark_dir =  get_observer_folder(rs, program_name);
        rs.process_manager.run(node_name+"_cap", command, tshark_dir, tshark_dir);
    }

    path extract_pcap_to_csv(const string& actor_name, const path& real_folder){
        const path pcap_path = real_folder / (actor_name+"_capture.pcap");
        const path csv_path = real_folder / (actor_name+".csv");

        const vector<string> gen_cmd = {
            "tshark",
            "-l",
            "-t", "ad",
            "-r", pcap_path.string(),
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time",
            "-e", "frame.len",
            "-E", "separator=,"
        };

        const string csv_output = hw_capabilities::run_cmd_output(gen_cmd);

        ofstream csv_file(csv_path);
        if (!csv_file.is_open()) {
            throw runtime_error("Failed to write CSV: "+csv_path.string());
        }
        csv_file << csv_output;
        csv_file.close();

        return csv_path;
    };

    pair<vector<LogTimePoint>, vector<double>> times_packet_sizes_from_csv(const path& csv_path){
        vector<LogTimePoint> times;
        vector<double> sizes;

        ifstream file(csv_path.string());
        string line;

        while (getline(file, line)) {
            stringstream ss(line);
            string frame_num_str, t_str, s_str;
            if (getline(ss, frame_num_str, ',') && getline(ss, t_str, ',') && getline(ss, s_str, ',')) {
                try {
                    const LogTimePoint tp = log_time_to_epoch_ns(t_str);
                    if (tp.time_since_epoch().count() == 0) continue;
                    times.push_back(tp);
                    sizes.push_back(stod(s_str));
                } catch (...) {}
            }
        }
        return {times, sizes};
    }

    LogTimePoint get_pcap_start_time(const string& pcap_path) {
        const vector<string> get_start_cmd = {
            "tshark","-t","ad", "-r", pcap_path,
            "-T", "fields", "-e", "frame.time", "-c", "1"
        };

        string start_str = hw_capabilities::run_cmd_output(get_start_cmd);
        start_str.erase(0, start_str.find_first_not_of(" \n\r\t"));
        start_str.erase(start_str.find_last_not_of(" \n\r\t") + 1);

        //debug if (start_str.empty()){throw runtime_error("Failed to get ISO start time from PCAP: "+pcap_path);}
        return log_time_to_epoch_ns(start_str);
    }
    vector<LogTimePoint> get_tshark_events(const RunStatus& rs, const string& process_name, const string& tshark_filter, const string& event_name) {
        vector<LogTimePoint> timestamps;
        const path pcap_path = get_observer_folder(rs, program_name) / (process_name+"_capture.pcap");
        if (!exists(pcap_path)) {
            log(LogLevel::ERROR, "Could not find file '"+pcap_path.string()+"'");
            return {};
        }

        const vector<string> gen_cmd = {
            "tshark",
            "-l",
            "-t", "ad",
            "-r", pcap_path.string(),
            "-Y", tshark_filter,
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time"
        };

        const string csv_output = hw_capabilities::run_cmd_output(gen_cmd);

        const path csv_path = get_observer_folder(rs, program_name) / (process_name+"_"+event_name +".csv");
        ofstream csv_file(csv_path);
        if (csv_file.is_open()) {csv_file << csv_output;csv_file.close();}

        istringstream stream(csv_output);
        string line;
        while (getline(stream, line)) {
            line.erase(0, line.find_first_not_of(" \n\r\t"));
            line.erase(line.find_last_not_of(" \n\r\t") + 1);
            if (line.empty()) continue;

            try {
                // Parse line: frame_in_batch,timestamp
                stringstream ss(line);
                string frame_num_str, time_str;
                if (getline(ss, frame_num_str, '\t') && getline(ss, time_str)) {
                    const LogTimePoint tp = log_time_to_epoch_ns(time_str);
                    if (tp.time_since_epoch().count() != 0) {
                        timestamps.push_back(tp);
                    }
                }
            } catch (const exception& e) { log(LogLevel::WARNING, "Failed to parse timestamp '"+line+"':"+e.what());}
        }

        log(LogLevel::INFO, "Extracted %zu timestamps matching filter '%s'", timestamps.size(), tshark_filter.c_str());
        return timestamps;
    }

    void pcap_events(
        const RunStatus& rs,
        vector<unique_ptr<GraphElements>>& elements,
        // { actor, filter, label, color }
        initializer_list<tuple<string, string, string, string>> event_def)
    {
        for (auto& [actor, filter, label, color] : event_def) {
            elements.push_back(make_unique<EventLines>(
                get_tshark_events(rs, actor, filter, label), label, color));
        }
    }

    string tshark_graph(const RunStatus &rs,
                    const string &actor_name,
                    const vector<unique_ptr<GraphElements>>& elements,
                    const path &folder){
        const path real_folder = folder.empty() ? get_observer_folder(rs, program_name) : folder;
        create_directories(real_folder);

        const path output_path = real_folder / (actor_name +"_graph.png");
        const path csv_path = extract_pcap_to_csv(actor_name, real_folder);

        auto [times, sizes] = times_packet_sizes_from_csv(csv_path);
        const path pcap_path = real_folder / (actor_name +"_capture.pcap");
        const auto start_time = get_pcap_start_time(pcap_path);
        transform_to_relative(times, start_time);

        if (times.empty() || sizes.empty() || times.size() != sizes.size())
            throw runtime_error("Invalid traffic data");

        auto g = Graph();
        g.axis = TimeAxis::RELATIVE;
        g.start_time = start_time;

        g.file = popen("gnuplot", "w");
        if (!g.file) throw runtime_error("Failed to start gnuplot");

        g.gpcmd("set terminal pngcairo size 1600,900 enhanced font 'Arial,10'");
        g.gpcmd("set output '"+output_path.string() +"'");
        g.gpcmd("set grid");
        g.gpcmd("set xlabel 'Time (s)'");
        g.gpcmd("set ylabel 'Packet Size'");

        auto [min_it, max_it] = minmax_element(sizes.begin(), sizes.end());
        g.ymin = *min_it;
        g.ymax = *max_it;

        double pad = (g.ymax - g.ymin) * 0.5;
        if (pad == 0) pad = 1.0;
        g.ymin -= pad;
        g.ymax += pad;

        g.gpcmd("set tmargin 5");
        g.gpcmd("set bmargin 5");

        // traffic
        g.add_XY_points(*make_unique<GraphXYPoints>(times, sizes, "traffic"));
        g.gpcmd(escape_tex("set title 'Network Traffic - "+actor_name +"'"));

        // events
        g.add_graph_elements(elements);

        g.render();
        return output_path.string();
    }

    // ------------ retransmission graph ---------------
    void generate_time_series_retry_graph(const RunStatus &rs,
                    const string &actor_name,
                    const path &folder) {
        const path real_folder = folder.empty() ? get_observer_folder(rs, program_name) : folder;
        create_directories(real_folder);
        const path output_path = real_folder / (actor_name +"_g.png");
        const path pcap_path = real_folder / (actor_name +"_capture.pcap");

        // [relative time] [ retry? (True/False)]
        const string cmd = "tshark -r " + pcap_path.string() +
                    // " -Y \"wlan.addr == " + mac+"\" " +
                     " -T fields -e frame.time_relative -e wlan.fc.retry";

        // parse tshark
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return;

        // second -> {all_frames, retries}
        // rounded for  0.1s
        map<double, pair<int, int>> stats_map;

        char buffer[256];
        char ts_buf[64], retry_buf[64];
        while (fgets(buffer, sizeof(buffer), pipe)) {
            if (sscanf(buffer, "%63s %63s", ts_buf, retry_buf) == 2) {
                const double timestamp = std::atof(ts_buf);
                const int is_retry = (strcmp(retry_buf, "True") == 0) ? 1 : 0;

                double bin = floor(timestamp * 10.0) / 10.0;
                stats_map[bin].first++;
                if (is_retry) stats_map[bin].second++;
            }
        }
        pclose(pipe);

        //create graph
        auto g = Graph();
        g.file = popen("gnuplot", "w");
        g.gpcmd("set terminal pngcairo size 1200,600");
        g.gpcmd("set output '"+output_path.string()+"'");
        g.gpcmd("set title 'Retransmit Rate over Time '");
        g.gpcmd("set xlabel 'Time (s)'\n");
        g.gpcmd("set ylabel 'Retry Percentage (%%)'");
        g.gpcmd("set yrange [0:110]");
        g.gpcmd("set grid");
        g.gpcmd("set style fill transparent solid 0.5 noborder");

        g.gpcmd("$MyData << EOD");
        for (auto const& [time, counts] : stats_map) {
            double percent = (counts.first > 0) ? (static_cast<double>(counts.second) / counts.first) * 100.0 : 0.0;
            fprintf(g.file, "%f %f\n", time, percent);
        }
        g.gpcmd("EOD");

        g.gpcmd("plot $MyData using 1:2 with impulses title 'Retransmit Rate' lc rgb 'red', "
                    "$MyData using 1:2 with points pt 7 ps 0.5 lc rgb '#8B0000' notitle");

        g.render();
    }
}

