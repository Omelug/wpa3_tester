#pragma once
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include <boost/pfr.hpp>
#include <nlohmann/json.hpp>

#include "config/RunStatus.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/log.h"
#include "overview/described.h"

class GraphElements;

namespace wpa3_tester::suite::helper{
std::optional<nlohmann::json> load_result_json(const std::filesystem::path &test_folder);

TimeWindow get_run_window(const RunStatus &rs);

std::pair<std::optional<bool>, std::optional<hostapd::CrackResult>>

//helper function
// DISCLAIMER: some helpers only works for ap, client, attacker and rogue_ap
hostapd_mana_crack(const RunStatus &rs, std::vector<std::unique_ptr<GraphElements>> &elements);
described_bool get_ap_ocv(const RunStatus &rs);
described_bool get_client_ocv(const RunStatus &rs);
described_str get_client_mfp(const RunStatus &rs, TimeWindow window = {});
described_str get_client_WPA_support(const RunStatus &rs, TimeWindow window = {});
described_str get_conn_WPA_version(const RunStatus &rs, TimeWindow window = {});
described_bool get_client_disconnected(const RunStatus &rs, TimeWindow window = {});
described_str get_ap_WPA_support(const RunStatus &rs);
described_str get_client_scanning(const RunStatus &rs, TimeWindow window = {});

// Entry templeate
template<typename T> inline constexpr bool is_optional_field = false;
template<typename T> inline constexpr bool is_optional_field<std::optional<T>> = true;

// display-only fields: never stored in result.json
template<typename T> inline constexpr bool is_pair_field = false;
template<typename A, typename B> inline constexpr bool is_pair_field<std::pair<A, B>> = true;

template<typename T> T entry_default(){ return T{}; }
template<> inline std::string                   entry_default<std::string>()                   { return "-";   }
template<> inline std::optional<std::string>    entry_default<std::optional<std::string>>()    { return "N/A"; }

// load field values by matching field name to JSON key
template<typename Entry>
Entry load_result_default(const nlohmann::json &result){
	Entry e;
	boost::pfr::for_each_field(e, [&]<typename param_type, std::size_t I>(param_type &field, std::integral_constant<std::size_t, I>){
		constexpr std::string_view param_name = boost::pfr::get_name<I, Entry>();
		using F = std::decay_t<param_type>;
		if constexpr(!is_pair_field<F>){
			if(result.contains(param_name)) {
				if constexpr(is_optional_field<F>){
					if (!result.at(param_name).is_null()) {
						field = result.at(param_name).get<typename F::value_type>();
					} else {
						field = std::nullopt;
					}
				}else {
					result.at(param_name).get_to(field);
				}
			} else {
				field = entry_default<F>();
			}
		}
	});
	return e;
}

template<typename Entry>
Entry load_result_default(const std::filesystem::path &test_folder){
	const auto result = load_result_json(test_folder);
	if(!result) return Entry{};
	return load_result_default<Entry>(*result);
}

}
