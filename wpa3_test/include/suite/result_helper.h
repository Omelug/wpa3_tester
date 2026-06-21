#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#if defined(__CLION_IDE__)
	#ifndef BOOST_PFR_CORE_NAME_PARSING
		#define BOOST_PFR_CORE_NAME_PARSING (2, 2, "")
	#endif
#endif

#include <boost/pfr.hpp>
#include <nlohmann/json.hpp>

namespace wpa3_tester::suite::helper{
std::optional<nlohmann::json> load_result_json(const std::filesystem::path &test_folder);

template<typename T> inline constexpr bool is_optional_field = false;
template<typename T> inline constexpr bool is_optional_field<std::optional<T>> = true;

template<typename T> T entry_default(){ return T{}; }
template<> inline std::string                   entry_default<std::string>()                   { return "-";   }
template<> inline std::optional<std::string>    entry_default<std::optional<std::string>>()    { return "N/A"; }

template<typename Entry>
Entry load_result_default(const std::filesystem::path &test_folder){
	Entry e;
	const auto result = load_result_json(test_folder);
	if(!result) return e;

	constexpr auto field_names = boost::pfr::names_as_array<Entry>();

	boost::pfr::for_each_field(e, [&]<typename param_type>(param_type &field, std::size_t idx){
		const std::string param_name{field_names[idx]};
		using F = std::decay_t<param_type>;
		if(result->contains(param_name)){
			if constexpr(is_optional_field<F>)
				field = result->at(param_name).get<typename F::value_type>();
			else
				result->at(param_name).get_to(field);
		} else {
			field = entry_default<F>();
		}
	});

	return e;
}

}
