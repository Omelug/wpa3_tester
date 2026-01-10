#include "observer/observers.h"

#include "logger/log.h"


namespace wpa3_tester::observer{
    using namespace std;
    using namespace filesystem;
    void add_nets(const RunStatus& run_status, std::vector<std::string>& command, const std::string& src_name){
        if(!run_status.config["actors"][src_name].contains("netns")){return;}
        const auto netns_node = run_status.config["actors"][src_name]["netns"];
        if (!netns_node.is_null()) {
            auto netns_client = netns_node.get<string>();
            command.insert(command.end(), {"ip", "netns", "exec", netns_client});
        }
    }

    path get_observer_folder(const RunStatus& rs,const string& observer_name){
        const path obs_dir = path(rs.run_folder) / "observer" / observer_name;
        error_code ec;
        create_directories(obs_dir, ec);
        if (ec) {
            log(LogLevel::ERROR,
                "Failed to create iperf3 observer dir %s: %s",
                obs_dir.string().c_str(), ec.message().c_str());
        }
        return obs_dir;
    }
}
