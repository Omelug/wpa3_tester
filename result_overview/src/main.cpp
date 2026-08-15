#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

#include "default.h"
#include "attacks/DoS_soft/bl0ck.h"
#include "attacks/DoS_soft/channel_switch.h"
#include "attacks/DoS_soft/malformed_eapol1.h"
#include "attacks/downgrade/owe_trans.h"
#include "attacks/downgrade/wpa3_trans_downgrade.h"
#include "devices.h"
#include "target.h"
#include "system/utils.h"

using namespace std;
using namespace filesystem;

static path project_root() {
	char buf[4096]{};
	const ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
	if (len <= 0) return current_path();
	return path(buf).parent_path().parent_path().parent_path();
}

static void print_usage(const char* argv0) {
	fprintf(stderr,
		"Usage: %s [--data_dir <path>] [--output_dir <path>]\n"
		"  --data_dir    path to data directory (default: <project_root>/data)\n"
		"  --output_dir  path to output directory (default: <project_root>/build/result_overview)\n",
		argv0);
}

struct Args {
	path data_dir;
	path output_dir;
};

static Args parse_args(int argc, char* argv[]) {
	const path root = project_root();
	Args a{ root / "data", root / "build" / "result_overview" };
	for (int i = 1; i < argc; ++i) {
		const string_view arg = argv[i];
		if ((arg == "--data_dir" || arg == "--output_dir") && i + 1 < argc) {
			path& target = (arg == "--data_dir") ? a.data_dir : a.output_dir;
			target = argv[++i];
		} else if (arg == "--help" || arg == "-h") {
			print_usage(argv[0]);
			exit(0);
		} else {
			fprintf(stderr, "Unknown argument: %s\n", string(arg).c_str());
			print_usage(argv[0]);
			exit(1);
		}
	}
	return a;
}

static string html_page() {
	ostringstream out;
	out << R"html(<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>WPA3 Tester — Results Overview</title>
	<link rel="stylesheet" href="style.css">
</head>
<body>
	<h1>WPA3 Tester — Results Overview</h1>

	<div class="card">
		<h2>Attack Categories</h2>
		<ul>
			<li><a href="attacks/DoS_soft/channel_switch/index.html">DoS Soft — Channel Switch (CSA)</a></li>
			<li><a href="attacks/DoS_soft/bl0ck/index.html">DoS Soft — Block ACK (Bl0ck)</a></li>
			<li><a href="attacks/DoS_soft/malformed_eapol1/index.html">DoS Soft — Malformed EAPOL-1</a></li>
			<li><a href="attacks/downgrade/owe_trans/index.html">downgrade — OWE Transition Probe Leak</a></li>
			<li><a href="attacks/downgrade/wpa3_trans_downgrade/index.html">downgrade — WPA3 Transition to WPA2-PSK</a></li>
			<li><a href="attacks/enterprise/invalid_curve/index.html">enterprise - invalid curve</a></li>
			<li><a href="attacks/enterprise/reflection_attack/index.html">enterprise - reflection</a></li>
		</ul>
	</div>

	<div class="card">
		<h2>
			<a href="devices/index.html">Devices</a>
		</h2>
	</div>

	<div class="card">
		<h2>
			<a href="target/index.html">Targets</a>
		</h2>
	</div>

</body>
</html>
)html";
	return out.str();
}

int main(int argc, char* argv[]) {
	const Args args        = parse_args(argc, argv);
	const path output_dir  = args.output_dir;
	const path data_dir    = args.data_dir;
	const path attacks_dir = project_root() / DATA_TEST / "src" / "attacks";

	wpa3_tester::create_public_dirs(output_dir);

	const path static_src = project_root() / "result_overview" / "static";
	if (exists(static_src))
		copy(static_src, output_dir, copy_options::recursive | copy_options::overwrite_existing);

	const path index = output_dir / "index.html";
	ofstream f(index);
	f << html_page();
	f.close();
	wpa3_tester::set_public_perms(index);

	wpa3_tester::overview::generate_devices(output_dir, data_dir);
	wpa3_tester::overview::generate_channel_switch(output_dir, data_dir);
	wpa3_tester::overview::generate_bl0ck(output_dir, data_dir);
	wpa3_tester::overview::generate_malformed_eapol1(output_dir, data_dir);
	wpa3_tester::overview::generate_owe_trans(output_dir, data_dir);
	wpa3_tester::overview::generate_wpa3_trans_downgrade(output_dir, data_dir);
	wpa3_tester::overview::generate_targets(output_dir, data_dir);

	return 0;
}
