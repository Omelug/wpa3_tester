#pragma once
#include <map>
#include <memory>
#include <string>
#include <utility>

// {src_mac, rx_mac} → dBm  (both keys normalized to lowercase)
using RssiMatrix = std::map<std::pair<std::string, std::string>, double>;

struct Expr {
	virtual ~Expr() = default;
	virtual bool eval(const RssiMatrix& m) const = 0;

	virtual std::vector<std::pair<std::string, std::string>> to_colored_parts(const RssiMatrix& m) const = 0;
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
//   "(aa:bb:cc:dd:ee:ff <-> 11:22:33:44:55:66) > -70 &&
//    !(aa:bb:cc:dd:ee:ff <-> 11:22:33:44:55:66) < -90"
ExprPtr parse_condition(const std::string& s);
