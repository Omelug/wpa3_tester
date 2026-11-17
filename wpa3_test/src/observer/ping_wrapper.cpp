#include "observer/ping_wrapper.h"
#include "config/RunStatus.h"
#include "observer/observers.h"
#include <filesystem>

namespace wpa3_tester::observer::ping {
using namespace std;
using namespace filesystem;

void start_ping(RunStatus &rs, const string &actor_name,
                const string &src_name, const string &dst_name) {
    const string dst_ip = rs.config().at("actors").at(dst_name).at("ip_addr");
    vector<string> command;
    add_nets_header(rs, command, src_name);
    command.insert(command.end(), { "stdbuf", "-oL",
        "ping", "-D", "-O", "-i", "1", "-W", "2", dst_ip });
    const path obs = get_observer_folder(rs, "ping");
    rs.process_manager.run(actor_name, command, obs, obs);
}
}
