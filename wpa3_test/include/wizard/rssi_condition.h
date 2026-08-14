#pragma once
#include "config/Actor_Config/actor_keys.h"
#include "system/wifi_channel.h"

#include <map>
#include <memory>
#include <string>
#include <tins/hw_address.h>
#include <utility>
#include <vector>

// Sentinel: no measurement available
inline constexpr double RSSI_NO_DATA = -90.0;

// {src_mac, rx_mac} -> dBm
using RssiMatrix = std::map<std::pair<Tins::HWAddress<6>, Tins::HWAddress<6>>, double>;

struct Expr {
    virtual ~Expr() = default;
    [[nodiscard]] virtual bool eval(const RssiMatrix&) const = 0;
    [[nodiscard]] virtual std::vector<std::pair<std::string, std::string>> to_colored_parts(const RssiMatrix&) const = 0;
};
using ExprPtr = std::unique_ptr<Expr>;

// Parse a condition string into an evaluable expression tree.
// Returns nullptr for an empty string.
// Throws std::runtime_error on parse failure.
//
// Grammar:
//   expr     = or_expr
//   or_expr  = and_expr  ( '||' and_expr  )*
//   and_expr = not_expr  ( '&&' not_expr  )*
//   not_expr = '!' not_expr | atom
//   atom     = value ('<'|'>') value | '(' expr ')'
//   value    = '(' mac '<->' mac ')' | NUMBER
//
// Example:
//   "(aa:bb:cc:dd:ee:ff <-> 11:22:33:44:55:66) > -70"
ExprPtr parse_condition(const std::string& s);
void render_condition_status(FILE* pipe, const ExprPtr& expr, const RssiMatrix& m);
//return true if found valid
bool run_rssi_wizard(const std::string& condition_str = "", const wpa3_tester::Channel &ch = {6, wpa3_tester::WifiBand::BAND_2_4, std::nullopt});
std::string actor_names_to_mac(const std::string &actor_names_cond,
	const std::vector<wpa3_tester::ActorCMap> &actors_maps);