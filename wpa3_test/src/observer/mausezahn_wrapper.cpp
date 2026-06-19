#include <filesystem>
#include "config/RunStatus.h"
#include "observer/observers.h"

namespace wpa3_tester::observer{
using namespace std;
using namespace filesystem;
using namespace nlohmann;

constexpr string program_name = "mausezahn";

void start_mausezahn(RunStatus &rs, const string &actor_name, const string &src_name, const string &dst_name){
	vector<string> command = {};
	add_nets_header(rs, command, src_name);

	command.insert(command.end(), {
						program_name, rs.get_actor(src_name)["iface"], "-d", "10m", // 10 millisecond
						"-c", "0",                                                  // not time limited
						"-p", "100",                                                // 100 bytes packet
						"-t", "udp", "sp=1234,dp=5201", "-a", rs.get_actor(src_name)["mac"], "-b",
						rs.get_actor(dst_name)["mac"], "-P", "PAYLOAD"
					});
	const path observer_dir = get_observer_folder(rs, program_name);
	rs.process_manager.run(actor_name, command, observer_dir, observer_dir);
}
}