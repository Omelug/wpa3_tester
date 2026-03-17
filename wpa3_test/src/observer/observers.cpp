#include "observer/observers.h"

#include "logger/log.h"


namespace wpa3_tester::observer{
    using namespace std;
    using namespace filesystem;
    void add_nets(const RunStatus& run_status, std::vector<std::string>& command, const std::string& src_name){
        if(!run_status.config.at("actors").at(src_name).contains("netns")){return;}
        const auto netns_node = run_status.config.at("actors").at(src_name).at("netns");
        if (!netns_node.is_null()) {
            auto netns_client = netns_node.get<string>();
            command.insert(command.end(), {"ip", "netns", "exec", netns_client});
        }
    }

    path get_observer_folder(const RunStatus& rs,const string& observer_name){
        const path obs_dir = path(rs.run_folder) / "observer" / observer_name;
        error_code ec;
        create_directories(obs_dir, ec);
        if (ec) {log(LogLevel::ERROR, "Failed to create "+observer_name+" observer dir "+obs_dir.string()+":"+ec.message());}
        return obs_dir;
    }
    void transform_to_relative(std::vector<LogTimePoint>& times, const LogTimePoint &start_time){
        if (times.empty()) return;
        const LogTimePoint t0 = start_time;
        for (auto& t : times) {
            auto rel = t - t0;
            t = LogTimePoint(std::chrono::duration_cast<std::chrono::nanoseconds>(rel));
        }
    }
}
