#pragma once
#include <string>
#include <vector>
#include "system/wifi_channel.h"

namespace wpa3_tester{

inline constexpr int FLAG_FAIL      = 1;
inline constexpr int FLAG_NOCAPTURE = 2;

class InjectionTestResult{
public:
	std::string test_name;
	int flags = 0;
	std::string detail = ""; // describes what failed; empty on pass

	[[nodiscard]] bool passed()     const{ return flags == 0; }
	[[nodiscard]] bool failed()     const{ return (flags & FLAG_FAIL) != 0; }
	[[nodiscard]] bool no_capture() const{ return (flags & FLAG_NOCAPTURE) != 0; }
	nlohmann::json to_json() const;
	static InjectionTestResult from_json(const nlohmann::json &j);
};

class InjectionSuiteResult{
public:
	std::string iface_out;
	std::string iface_in; // == iface_out for self-test
	std::string driver;
	Channel channel = {};
	std::vector<InjectionTestResult> tests;

	int overall_flags() const{
		int f = 0;
		for(const auto &t : tests) f |= t.flags;
		return f;
	}
	nlohmann::json to_json() const;
};

std::string print_injection_result(const InjectionSuiteResult &suite);

}
