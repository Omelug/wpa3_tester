#include "observer/dmesg_wrapper.h"
#include "config/RunStatus.h"
#include "observer/observers.h"

namespace wpa3_tester::observer::dmesg{
using namespace std;

void start_dmesg(RunStatus &rs, const string &actor_name){
	const string obs_folder = get_observer_folder(rs, "dmesg");
	rs.process_manager.run(actor_name + "_dmesg", {"dmesg", "-W"}, {}, obs_folder);
}
}
