#include <filesystem>
#include "config/RunStatus.h"
#include "observer/observers.h"
#include "observer/tshark_wrapper.h"
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>

#include "logger/log.h"
#include "../../include/observer/grapth/graph_utils.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester::observer{
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

            // Kontrola Address 1 (Příjemce - důležité pro ACK)
            // Offset 4 (4 bajty) a offset 8 (1 bajt)
            string addr1 = "(link[4:4] == 0x"+pre.substr(0, 8) +
                           " and link[8:1] == 0x"+pre.substr(8, 2)+")";

            // Kontrola Address 2 (Odesílatel - tvoje Probe Requesty)
            // Offset 10 (4 bajty) a offset 14 (1 bajt)
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
    string all_actors_mac_filter(const RunStatus &rs) {
        vector<string> mac_filters;

        for (const auto &actor: rs.actors | views::values) {
            mac_filters.push_back("ether host "+actor["mac"]);
        }
        mac_filters.push_back("ether host ff:ff:ff:ff:ff:ff");
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
                command.push_back(all_actors_mac_filter(rs));
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

    void times_packet_sizes_from_csv(vector<LogTimePoint> & times, vector<double> & sizes, path csv_path){
        ifstream file(csv_path.string());
        string line;

        // csv lines are in format frame_in_batch,epoch_time,size
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

    string tshark_graph(const RunStatus &rs,
                    const string &actor_name,
                    const vector<unique_ptr<GraphElements>>& elements,
                    const path &folder){
        const path real_folder = folder.empty() ? get_observer_folder(rs, program_name) : folder;
        create_directories(real_folder);

        path output_path = real_folder / (actor_name +"_graph.png");
        const path csv_path = extract_pcap_to_csv(actor_name, real_folder);

        vector<LogTimePoint> times;
        vector<double> sizes;
        times_packet_sizes_from_csv(times, sizes, csv_path);
        const path pcap_path = real_folder / (actor_name +"_capture.pcap");
        auto start_time = get_pcap_start_time(pcap_path);
        transform_to_relative(times, start_time);
        if (times.empty() || sizes.empty() || times.size() != sizes.size())
            throw runtime_error("Invalid traffic data");

        auto graph = Graph();
        graph.file = popen("gnuplot", "w");
        if (!graph.file) throw runtime_error("Failed to start gnuplot");

        auto gpcmd = [&](const string& cmd) { fprintf(graph.file, "%s\n", cmd.c_str());};

        gpcmd("set terminal pngcairo size 1600,900 enhanced font 'Arial,10'");
        gpcmd("set output '"+output_path.string() +"'");
        gpcmd("set grid");
        gpcmd("set xlabel 'Time (s)'");
        gpcmd("set ylabel 'Packet Size'");

        auto [min_it, max_it] = minmax_element(sizes.begin(), sizes.end());
        graph.ymin = *min_it;
        graph.ymax = *max_it;

        double pad = (graph.ymax - graph.ymin) * 0.5;
        if (pad == 0) pad = 1.0;
        graph.ymin  -= pad;
        graph.ymax  += pad;

        {
            ostringstream yr;
            gpcmd("set tmargin 5");
            gpcmd("set bmargin 5");
            gpcmd("set yrange ["+to_string( graph.ymin - pad) +":"+to_string(graph.ymax + pad) +"]");
            gpcmd(yr.str());
        }

        // traffic
        gpcmd("$traffic << EOD");
        for (size_t i = 0; i < times.size(); ++i) {
            double t = chrono::duration<double>(times[i].time_since_epoch()).count();
            ostringstream line;
            line << fixed << setprecision(9) << t << " " << sizes[i];
            gpcmd(line.str());
        }
        gpcmd("EOD");

        // events
        graph.plot_parts.emplace_back("$traffic using 1:2 with points pt 7 ps 0.7 lc rgb '#1f77b4' title 'Traffic'");
        graph.add_graph_elements(elements);

        gpcmd(escape_tex("set title 'Network Traffic - "+actor_name +"'"));

        //plot
        ostringstream plotcmd;
        plotcmd << "plot ";
        for (size_t i = 0; i < graph.plot_parts.size(); ++i) {
            plotcmd << graph.plot_parts[i];
            if (i + 1 < graph.plot_parts.size()) plotcmd << ", ";
        }
        gpcmd(plotcmd.str());
        fflush(graph.file);

        int rc = pclose(graph.file);
        if (rc != 0) throw runtime_error("Gnuplot failed");
        return output_path.string();
    }

    // ------------ retransmission graph ---------------
    void generate_time_series_retry_graph(const RunStatus &rs,
                    const string &actor_name,
                    const path &folder) {
        const path real_folder = folder.empty() ? get_observer_folder(rs, program_name) : folder;
        create_directories(real_folder);
        const path output_path = real_folder / (actor_name +"_graph.png");
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
        auto graph = Graph();
        graph.file = popen("gnuplot", "w");
        fprintf(graph.file, "set terminal pngcairo size 1200,600\n");
        fprintf(graph.file, "set output '%s'\n", output_path.c_str());
        fprintf(graph.file, "set title 'Retransmit Rate over Time '\n");
        fprintf(graph.file, "set xlabel 'Time (s)'\n");
        fprintf(graph.file, "set ylabel 'Retry Percentage (%%)'\n");
        fprintf(graph.file, "set yrange [0:110]\n");
        fprintf(graph.file, "set grid\n");
        fprintf(graph.file, "set style fill transparent solid 0.5 noborder\n");

        fprintf(graph.file, "$MyData << EOD\n");
        for (auto const& [time, counts] : stats_map) {
            double percent = (counts.first > 0) ? (static_cast<double>(counts.second) / counts.first) * 100.0 : 0.0;
            fprintf(graph.file, "%f %f\n", time, percent);
        }
        fprintf(graph.file, "EOD\n");

        fprintf(graph.file, "plot $MyData using 1:2 with impulses title 'Retransmit Rate' lc rgb 'red', "
                    "$MyData using 1:2 with points pt 7 ps 0.5 lc rgb '#8B0000' notitle \n");

        fflush(graph.file);
        pclose(graph.file);
    }
}

