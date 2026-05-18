#include "attacks/two_iface/TwoIfaceActive.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester {
using namespace std;
using nlohmann::json;

TwoIfaceActive::TwoIfaceActive()
: TwoIface({{SK::driver_name, SK::driver_hash}, {BK::monitor, BK::active_monitor}}, "active_test"){}

json TwoIfaceActive::run(const ActorPtr &a1, const ActorPtr &a2){
	constexpr Channel ch = {};
	bool ok1 = false, ok2 = false;

	//TODO  generate config for scan/active_test.cpp to data/two_iface/active_test/config/<file>
	// run RunStatus with config <>
	if(const auto &iface1 = a1[SK::iface]; iface1.has_value()){
		ok1 = hw_capabilities::set_monitor_active(*iface1, a1[SK::netns], ch);
		log(LogLevel::DEBUG, "active_test: {} -> {}", *iface1, ok1 ? "ok" : "fail");
	}
	if(const auto &iface2 = a2[SK::iface]; iface2.has_value()){
		ok2 = hw_capabilities::set_monitor_active(*iface2, a2[SK::netns], ch);
		log(LogLevel::DEBUG, "active_test: {} -> {}", *iface2, ok2 ? "ok" : "fail");
	}

	return json{{"actor1_ok", ok1}, {"actor2_ok", ok2} };
}

bool TwoIfaceActive::run_check(const ActorPtr &a1, const ActorPtr &a2){
	TwoIfaceActive t;
	const bool both_ok = t.validate(a1, a2).value("both_ok", false);
	if(!both_ok)
		log(LogLevel::WARNING, "active_test: actors {}/{} failed active monitor check",
			a1[SK::actor_name].value_or("?"), a2[SK::actor_name].value_or("?"));
	return !both_ok; // true = need re-assignment
}

} // namespace wpa3_tester
