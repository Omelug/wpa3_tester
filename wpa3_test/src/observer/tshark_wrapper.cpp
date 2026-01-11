#include <filesystem>
#include "config/RunStatus.h"
#include "observer/observers.h"
#include <matplot/matplot.h>

#include "system/hw_capabilities.h"

namespace wpa3_tester::observer{
    using namespace std;
    using namespace filesystem;
    namespace mp = matplot;

    constexpr string program_name = "tshark";
    void start_thark(RunStatus &run_status, const string &node_name) {
        vector<string> command = {"sudo"};
        add_nets(run_status,command, node_name);

        string pcap_path = get_observer_folder(run_status, program_name) / (node_name + "_capture.pcap");
        command.insert(command.end(), {
            program_name, "-i", run_status.get_actor(node_name)["iface"],
            "-w", pcap_path,
            "-f", "udp port 5201", //TODO hardcoded
        });

        run_status.process_manager.run(node_name + "_cap", command, get_observer_folder(run_status, program_name));
    }

    string tshark_graph(const RunStatus &run_status, const string &node_name) {
        string pcap_path = get_observer_folder(run_status, program_name) / (node_name + "_capture.pcap");
        string csv_path = get_observer_folder(run_status, program_name) / (node_name + ".csv");
        string graph_path = get_observer_folder(run_status, program_name) / (node_name + "_graph.png");

        vector<string> gen_cmd = {
            "sh", "-c",
            "tshark -r " + pcap_path + " -T fields -e frame.time_relative -e frame.len -E separator=, > " + csv_path
        };
        hw_capabilities::run_cmd(gen_cmd);

        vector<double> times, sizes;
        ifstream file(csv_path);
        string line;

        while (getline(file, line)) {
            stringstream ss(line);
            string t, s;
            if (getline(ss, t, ',') && getline(ss, s, ',')) {
                try {
                    times.push_back(stod(t));
                    sizes.push_back(stod(s));
                } catch (...) {
                    cerr << "Invalid row in csv: " << line << endl;
                }
            }
        }

        auto f = mp::figure();
        f->quiet_mode(true);
        f->width(1200);
        f->height(700);

        auto ax = f->current_axes();
        ax->ylim({1, 3000});

        vector<double> y = sizes;

        for (auto& v : y) {
            if (v <= 0.0){
                constexpr double eps = 1e-3;
                v = eps;
            }
        }

        ax->xlabel("Time [s]");
        ax->ylabel("Size [B]");
        ax->title("Traffic: " + node_name);

        auto p = ax->semilogy(times, y, "ro");
        p->marker_size(6);
        p->marker_face_color({0, 0.5, 0.5});
        p->display_name("Packet size ");
        f->save(graph_path);
        return graph_path;
    }
}

