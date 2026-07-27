#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <boost/pfr.hpp>
#include <nlohmann/json.hpp>
#include "overview/described.h"

namespace wpa3_tester::suite::helper{
std::optional<nlohmann::json> load_result_json(const std::filesystem::path &test_folder);

template<typename T> inline constexpr bool is_optional_field = false;
template<typename T> inline constexpr bool is_optional_field<std::optional<T>> = true;

// display-only fields: never stored in result.json
template<typename T> inline constexpr bool is_pair_field = false;
template<typename A, typename B> inline constexpr bool is_pair_field<std::pair<A, B>> = true;
template<> inline constexpr bool is_pair_field<described_bool> = true;
template<> inline constexpr bool is_pair_field<described_str>  = true;

template<typename T> T entry_default(){ return T{}; }
template<> inline std::string                   entry_default<std::string>()                   { return "-";   }
template<> inline std::optional<std::string>    entry_default<std::optional<std::string>>()    { return "N/A"; }

template<typename Entry>
Entry load_result_default(const std::filesystem::path &test_folder){
	Entry e;
	const auto result = load_result_json(test_folder);
	if(!result) return e;

	boost::pfr::for_each_field(e, [&]<typename param_type, std::size_t I>(param_type &field, std::integral_constant<std::size_t, I>){
		constexpr std::string_view param_name = boost::pfr::get_name<I, Entry>();
		using F = std::decay_t<param_type>;
		if constexpr(!is_pair_field<F>){ // pair fields are display-only, never in result.json
			if(result->contains(param_name)){
				if constexpr(is_optional_field<F>)
					field = result->at(param_name).get<typename F::value_type>();
				else
					result->at(param_name).get_to(field);
			} else {
				field = entry_default<F>();
			}
		}
	});

	return e;
}

}
