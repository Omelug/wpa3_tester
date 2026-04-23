#pragma once
#include <string>

#include "tshark_wrapper.h"
#include "config/RunStatus.h"

namespace wpa3_tester::observer::station_counter{
inline const std::string SUFFIX_sta = "_sta";

static void start_remote(RunStatus &rs,
                         const std::string &actor_name,
                         int interval_sec,
                         const std::string &local_log
);
static void start_local(RunStatus &rs,
                        const std::string &actor_name,
                        const std::string &iface,
                        int interval_sec
);
void start_station_monitoring(RunStatus &rs, const std::string &actor_name, int interval_sec);
void generate_station_graph(const std::string &data_filepath,
                            const std::string &output_imagepath,
                            G_el elements
);
void create_station_graph(const RunStatus &rs,
                          const std::string &actor_name,
                          const std::vector<std::unique_ptr<GraphElements>> &elements = {}
);
}