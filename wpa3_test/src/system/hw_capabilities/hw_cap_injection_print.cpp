#include "system/injection_result.h"
#include <sstream>

namespace wpa3_tester{
using namespace std;

static const char *md_badge(const int flags){
	if(flags & FLAG_NOCAPTURE) return "NO-CAPTURE";
	if(flags & FLAG_FAIL)      return "FAIL";
	return                            "PASS";
}

string print_injection_result(const InjectionSuiteResult &suite){
	ostringstream md;

	md << "## Injection Test Results\n\n";

	md << "| Property | Value |\n";
	md << "|----------|-------|\n";
	md << "| Interface (inject) | `" << suite.iface_out << "` |\n";
	if(suite.iface_in != suite.iface_out)
		md << "| Interface (monitor) | `" << suite.iface_in << "` |\n";
	md << "| Driver | " << suite.driver << " |\n";
	md << "| Channel | " << suite.channel.ch_num << " |\n\n";

	md << "### Results\n\n";
	md << "| Test | Status | Detail |\n";
	md << "|------|--------|--------|\n";
	for(const auto &[test_name, flags, detail] : suite.tests){
		md << "| `" << test_name << "` | **" << md_badge(flags) << "** | ";
		md << (detail.empty() ? "" : detail) << " |\n";
	}
	md << '\n';

	const int f = suite.overall_flags();
	if(f == 0){
		md << "> **All tests passed.**\n";
	} else{
		if(f & FLAG_NOCAPTURE)
			md << "> **WARNING:** Failed to capture some frames. Try another channel or a second monitoring interface.\n";
		if(f & FLAG_FAIL)
			md << "> **FAIL:** Some tests failed. Consider using patched drivers/firmware.\n";
	}
	md << '\n';

	return md.str();
}

}
