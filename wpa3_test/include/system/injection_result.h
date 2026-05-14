#pragma once
#include <string>
#include <vector>

namespace wpa3_tester{

inline constexpr int FLAG_FAIL      = 1;
inline constexpr int FLAG_NOCAPTURE = 2;

struct InjectionTestResult{
	std::string name;
	int flags = 0;
	std::string detail = ""; // describes what failed; empty on pass

	[[nodiscard]] bool passed()     const{ return flags == 0; }
	[[nodiscard]] bool failed()     const{ return (flags & FLAG_FAIL) != 0; }
	[[nodiscard]] bool no_capture() const{ return (flags & FLAG_NOCAPTURE) != 0; }
};

struct InjectionSuiteResult{
	std::string iface_out;
	std::string iface_in; // == iface_out for self-test
	std::string driver;
	int channel = 0;
	std::vector<InjectionTestResult> tests;

	int overall_flags() const{
		int f = 0;
		for(const auto &t : tests) f |= t.flags;
		return f;
	}
};

std::string print_injection_result(const InjectionSuiteResult &suite);

}
