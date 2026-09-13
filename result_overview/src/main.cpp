#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

#include "attacks/DoS_soft/bl0ck.h"
#include "attacks/DoS_soft/channel_switch.h"
#include "attacks/DoS_soft/deauth.h"
#include "attacks/DoS_soft/expected_vht_beacon.h"
#include "attacks/DoS_soft/malformed_eapol1.h"
#include "attacks/downgrade/owe_trans.h"
#include "attacks/downgrade/wpa3_trans_downgrade.h"
#include "attacks/enterprise/invalid_curve.h"
#include "attacks/enterprise/reflection_attack.h"
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/ssid_confusion.h"
#include "attacks/two_iface/injection_overview.h"
#include "default.h"
#include "devices.h"
#include "observer/observers_showcase.h"
#include "system/utils.h"
#include "target.h"

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

static Args parse_args(const int argc, char* argv[]) {
	const path root = project_root();
	Args a{ root / DATA_DIR, root / "build" / "result_overview" };
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
	<title>WPA3 Tester - Results Overview</title>
	<link rel="stylesheet" href="style.css">
</head>
<body>
	<h1>WPA3 Tester - Results Overview</h1>

	<div class="card">
		<h2>Attack Categories</h2>
		<h3>DoS_soft<h3>
		<ul>
			<li><a href="attacks/DoS_soft/channel_switch/index.html">channel Switch (CSA)</a></li>
			<li><a href="attacks/DoS_soft/bl0ck/index.html">bl0ck attacks</a></li>
			<li><a href="attacks/DoS_soft/malformed_eapol1/index.html">malformed EAPOL-1</a></li>
			<li><a href="attacks/DoS_soft/expected_vht_beacon/index.html">fake legacy(no HT/VHT) beacon DoS </a></li>
			<li><a href="attacks/DoS_soft/deauth/index.html">deauthentication DoS</a></li>
		</ul>

		<h3>downgrade<h3>
		<ul>
			<li><a href="attacks/downgrade/owe_trans/index.html">OWE Transition Probe Leak</a></li>
			<li><a href="attacks/downgrade/wpa3_trans_downgrade/index.html">WPA3 Transition to WPA2-PSK</a></li>
		</ul>

		<h3>enterprise<h3>
		<ul>
			<li><a href="attacks/enterprise/invalid_curve/index.html">invalid curve</a></li>
			<li><a href="attacks/enterprise/reflection_attack/index.html">reflection attack</a></li>
		</ul>

		<h3>two_iface<h3>
		<ul>
			<li><a href="attacks/two_iface/injection/index.html">two_iface - injection test cache</a></li>
		</ul>

		<h3>mc_mitm<h3>
		<ul>
			<li><a href="attacks/mc_mitm/mc_mitm/index.html">multi-channel MitM</a></li>
			<li><a href="attacks/mc_mitm/ssid_confusion/index.html">SSID confusion</a></li>
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

	<hr style="margin: 32px 0; border: none; border-top: 2px solid #3498db;">
	<h2> Tester Info</h2>

	<div class="card">
		<h2>
			<a href="observer/showcase/index.html">observer graphs showcase</a>
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
	const path data_dir    = absolute(args.data_dir);
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
	wpa3_tester::overview::generate_deauth(output_dir, data_dir);
	wpa3_tester::overview::generate_malformed_eapol1(output_dir, data_dir);
	wpa3_tester::overview::generate_expected_vht_beacon(output_dir, data_dir);
	wpa3_tester::overview::generate_owe_trans(output_dir, data_dir);
	wpa3_tester::overview::generate_wpa3_trans_downgrade(output_dir, data_dir);
	wpa3_tester::overview::generate_targets(output_dir, data_dir);
	wpa3_tester::overview::generate_invalid_curve_attack(output_dir, data_dir);
	wpa3_tester::overview::generate_reflection_attack(output_dir, data_dir);
	wpa3_tester::overview::generate_injection_overview(output_dir, data_dir);
	wpa3_tester::overview::generate_mc_mitm(output_dir, data_dir);
	wpa3_tester::overview::generate_ssid_confusion(output_dir, data_dir);
	wpa3_tester::overview::generate_observers_showcase(output_dir, data_dir);

	return 0;
}
