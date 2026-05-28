#pragma once
#include <string>
#include <vector>
#include "system/wifi_channel.h"

namespace wpa3_tester{

enum it_test_result{
	UNKNOWN,
	PASSED,
	FAIL,
	NOCAPTURE
};

inline std::string result_to_string(const it_test_result r){
	switch(r){
	case PASSED:    return "PASSED";
	case FAIL:      return "FAIL";
	case NOCAPTURE: return "NOCAPTURE";
	default:        return "UNKNOWN";
	}
}

inline it_test_result it_test_result_from_string(std::string_view s){
	if(s == "PASSED")    return PASSED;
	if(s == "FAIL")      return FAIL;
	if(s == "NOCAPTURE") return NOCAPTURE;
	return UNKNOWN;
}

class InjectionTestResult{
protected:
	std::string _test_name;
	it_test_result _result = UNKNOWN;
	std::string _detail = ""; // describes what failed; empty on pass
public:
	[[nodiscard]] std::string test_name() const{ return _test_name; }
	void test_name(const std::string &test_name) { _test_name = test_name; }
	[[nodiscard]] it_test_result result() const{ return _result; }
	void result(const it_test_result &result) { _result = result; }
	[[nodiscard]] std::string detail()    const{ return _detail; }
	void detail(const std::string &detail) { _detail = detail; }

	nlohmann::json to_json() const{
		auto j = nlohmann::json();
		j[_test_name] = {{"result", result_to_string(_result)}, {"detail", _detail}};
		return j;
	}

	explicit InjectionTestResult() = default;
	InjectionTestResult(const std::string &test_name, const it_test_result result, const std::string &detail = ""):
	_test_name(test_name), _result(result), _detail(detail){};

	//explicit InjectionTestResult(const nlohmann::json &j);
};

class InjectionSuiteResult{
public:
	std::string iface_out;
	std::string iface_in; // == iface_out for self-test
	std::string driver;
	Channel channel;
	std::vector<InjectionTestResult> tests;

	it_test_result inject_all() const{
		for(const auto &t : tests){
			if(t.result() != PASSED) return FAIL;
		}
		return PASSED;

	}
	nlohmann::json to_json() const{
		nlohmann::json map = nlohmann::json::object();
		for(const auto &t: tests)
			map[t.test_name()] = {{"result", result_to_string(t.result())}, {"detail", t.detail()}};
		return {{"tests", map}};
	}
};

std::string print_injection_result(const InjectionSuiteResult &suite);

}
