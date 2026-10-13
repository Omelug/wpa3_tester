#include "observer/wpa_cli_poller.h"
#include "config/RunStatus.h"
#include "observer/observers.h"
#include "system/utils.h"
#include <string>
#include <vector>

namespace wpa3_tester::observer::wpa_cli_poller {
using namespace std;

static const string program_name = "wpa_cli";

void start_wpa_cli_polling(RunStatus &rs, const string &actor_name, const int interval_sec) {
	const auto actor = rs.get_actor(actor_name);
	const string iface = actor.get(SK::iface);
	const auto obs_folder = get_observer_folder(rs, program_name);

	// Each iteration: print unix timestamp header then wpa_cli status output
	const string script =
		"while true; do echo \"=== $(date +%s) ===\"; "
		"wpa_cli -i " + iface + " status 2>&1; "
		"sleep " + to_string(interval_sec) + "; done";

	vector<string> cmd;
	add_nets_header(rs, cmd, actor_name);
	cmd.insert(cmd.end(), { "sh", "-c", script });

	rs.process_manager.run(actor_name + SUFFIX_wpa, cmd, {}, obs_folder);
}
}
