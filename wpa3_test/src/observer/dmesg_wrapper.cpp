#include "observer/dmesg_wrapper.h"
#include "config/RunStatus.h"
#include "observer/observers.h"

namespace wpa3_tester::observer::dmesg{
using namespace std;

void start_dmesg(RunStatus &rs, const string &actor_name, const string &level){
	const string obs_folder = get_observer_folder(rs, "dmesg");
	vector<string> args = {"dmesg", "-W"};
	if(!level.empty()) args.push_back("--level=" + level);
	rs.process_manager.run(actor_name + "_dmesg", args, {}, obs_folder);
}
}
