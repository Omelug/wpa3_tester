#include "observer/observers.h"

#include "logger/log.h"


namespace wpa3_tester::observer{
    using namespace std;
    using namespace filesystem;
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
