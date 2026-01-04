#pragma once
#include <filesystem>
#include <vector>

enum class PlotLibrary {
    SCIPLOT,
    MATPLOT
};

struct IperfData {
    std::vector<double> intervals;
    std::vector<double> bandwidths;
};

void iperf3_graph(const std::filesystem::path &log_path,
                         const std::string &actor_tag,
                         const std::string &output_png,
                         PlotLibrary lib = PlotLibrary::MATPLOT);
