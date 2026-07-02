#pragma once
#include <string>
#include <utility>
#include <vector>
#include "system/wifi_channel.h"

namespace wpa3_tester{
enum it_test_result{
	UNKNOWN,
	PASSED,
	FAIL,
	NOCAPTURE
};

NLOHMANN_JSON_SERIALIZE_ENUM(it_test_result, {
	{UNKNOWN, "UNKNOWN"},
	{PASSED, "PASSED"},
	{FAIL, "FAIL"},
	{NOCAPTURE, "NOCAPTURE"},
})

class InjectionTestResult{
protected:
	std::string _test_name;
	it_test_result _result = UNKNOWN;
	std::string _detail; // describes what failed; empty on pass
public:
	[[nodiscard]] std::string test_name() const{ return _test_name; }
	void test_name(const std::string &test_name){ _test_name = test_name; }
	[[nodiscard]] it_test_result result() const{ return _result; }
	void result(const it_test_result &result){ _result = result; }
	[[nodiscard]] std::string detail() const{ return _detail; }
	void detail(const std::string &detail){ _detail = detail; }

	[[nodiscard]] nlohmann::json to_json() const{
		auto j = nlohmann::json();
		j[_test_name] = {{"result", result()}, {"detail", _detail}};
		return j;
	}

	explicit InjectionTestResult() = default;

	InjectionTestResult(std::string test_name, const it_test_result result, std::string detail = ""
	): _test_name(std::move(test_name)), _result(result), _detail(std::move(detail)){};

	//explicit InjectionTestResult(const nlohmann::json &j);
};

class InjectionSuiteResult{
public:
	std::string iface_out;
	std::string iface_in; // == iface_out for self-test
	std::string driver;
	Channel channel;
	std::vector<InjectionTestResult> tests;

	[[nodiscard]] it_test_result inject_all() const{
		for(const auto &t: tests){
			if(t.result() != PASSED) return FAIL;
		}
		return PASSED;
	}

	[[nodiscard]] nlohmann::json to_json() const{
		nlohmann::json map = nlohmann::json::object();
		for(const auto &t: tests) map[t.test_name()] = {
			{"result", t.result()}, {"detail", t.detail()}
		};
		return {{"tests", map}};
	}
};

std::string print_injection_result(const InjectionSuiteResult &suite);
}
