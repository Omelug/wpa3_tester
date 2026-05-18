#include "attacks/two_iface/TwoIfaceInject.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "attacks/mc_mitm/MonitorSocket.h"

namespace wpa3_tester {
using namespace std;
using nlohmann::json;

TwoIfaceInject::TwoIfaceInject()
: TwoIface({{SK::driver_name, SK::driver_hash}, {BK::injection, BK::monitor}}, "two_iface_inject"){}

json TwoIfaceInject::run(const ActorPtr &a1, const ActorPtr &a2){
	const auto &iface1 = a1[SK::iface];
	const auto &iface2 = a2[SK::iface];

	if(!iface1.has_value() || !iface2.has_value())
		throw setup_err("inject_test: both actors must have an interface assigned");

	const Channel ch = a1->get_channel();
	hw_capabilities::setup_injection_iface(*iface1, ch, a1[SK::netns]);
	hw_capabilities::setup_injection_iface(*iface2, ch, a2[SK::netns]);

	MonitorSocket s_out(*iface1, a1[SK::netns]);
	MonitorSocket s_in(*iface2, a2[SK::netns]);

	const InjectionSuiteResult suite = hw_capabilities::run_injection_tests(s_out, *iface1, s_in, ch);

	const bool passed = (suite.overall_flags() == 0);
	log(passed ? LogLevel::INFO : LogLevel::WARNING, "inject_test: {}/{} -> {}", *iface1, *iface2,
		passed ? "passed" : "failed");

	return suite.to_json();
}

bool TwoIfaceInject::run_check(const ActorPtr &a1, const ActorPtr &a2){
	TwoIfaceInject t;
	const bool passed = (t.validate(a1, a2).value("overall_flags", 1) == 0);
	if(!passed)
		log(LogLevel::WARNING, "inject_test: actors {}/{} failed injection check",
			a1[SK::actor_name].value_or("?"), a2[SK::actor_name].value_or("?"));
	return !passed; // true = need re-assignment
}

}
