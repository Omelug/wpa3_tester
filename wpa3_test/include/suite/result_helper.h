#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include <boost/pfr.hpp>
#include <nlohmann/json.hpp>

namespace wpa3_tester::suite::helper{
std::optional<nlohmann::json> load_result_json(const std::filesystem::path &test_folder);

template<typename T> inline constexpr bool is_optional_field = false;
template<typename T> inline constexpr bool is_optional_field<std::optional<T>> = true;

template<typename Entry>
Entry load_result_default(const std::filesystem::path &test_folder){
	Entry e;
	const auto result = load_result_json(test_folder);
	if(!result) return e;

#if !defined(__clang__)  // PFR name extraction requires GCC — Clang uses different __PRETTY_FUNCTION__ format
	constexpr auto field_names = boost::pfr::names_as_array<Entry>();

	boost::pfr::for_each_field(e, [&]<typename param_type>(param_type &field, std::size_t idx){
		const std::string param_name{field_names[idx]};
		if(!result->contains(param_name)) return;
		using F = std::decay_t<param_type>;
		if constexpr(is_optional_field<F>)
			field = result->at(param_name).get<typename F::value_type>();
		else
			result->at(param_name).get_to(field);
	});
#endif
	return e;
}

}
