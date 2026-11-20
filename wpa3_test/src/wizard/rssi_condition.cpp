#include "wizard/rssi_condition.h"

#include "config/Actor_Config/ActorPtr.h"
#include "logger/log.h"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>
#include <tins/hw_address.h>
#include <utility>
#include <vector>

using namespace std;
//TODO simple tests for parsing

// ---- Tokenizer ----

enum class TokKind { LParen, RParen, And, Or, Not, Arrow, Lt, Le, Gt, Ge, Number, Mac, End };
struct Token {
	TokKind kind;
	string text;
	double num{};
	bool is_meters{ false };
};

static vector<Token> tokenize(const string &s) {
	vector<Token> toks;
	size_t i = 0;
	while(i < s.size()) {
		if(isspace(static_cast<unsigned char>(s[i]))) { ++i; continue; }
		const char c = s[i];
		auto peek = [&](size_t off, char ch) { return i + off < s.size() && s[i + off] == ch; };

		if(c == '(') { toks.push_back({ TokKind::LParen, "(" }); ++i; continue; }
		if(c == ')') { toks.push_back({ TokKind::RParen, ")" }); ++i; continue; }
		if(c == '!') { toks.push_back({ TokKind::Not,    "!" }); ++i; continue; }
		if(c == '&' && peek(1,'&')) { toks.push_back({ TokKind::And, "&&" }); i += 2; continue; }
		if(c == '|' && peek(1,'|')) { toks.push_back({ TokKind::Or,  "||" }); i += 2; continue; }
		if(c == '<') {
			if(peek(1,'-') && peek(2,'>')) { toks.push_back({ TokKind::Arrow, "<->" }); i += 3; continue; }
			if(peek(1,'='))                { toks.push_back({ TokKind::Le,    "<=" });  i += 2; continue; }
			toks.push_back({ TokKind::Lt, "<" }); ++i; continue;
		}
		if(c == '>') {
			if(peek(1,'=')) { toks.push_back({ TokKind::Ge, ">=" }); i += 2; continue; }
			toks.push_back({ TokKind::Gt, ">" }); ++i; continue;
		}

		if(i + 17 <= s.size()) {
			bool is_mac = true;
			for(int k = 0; k < 6 && is_mac; ++k)
				is_mac = isxdigit(static_cast<unsigned char>(s[i + k * 3])) &&
				         isxdigit(static_cast<unsigned char>(s[i + k * 3 + 1])) &&
				         (k == 5 || s[i+k*3+2] == ':');
			if(is_mac) { toks.push_back({ TokKind::Mac, s.substr(i, 17) }); i += 17; continue; }
		}

		if(c == '-' || isdigit(static_cast<unsigned char>(c))) {
			char *end;
			double val = strtod(s.c_str() + i, &end);
			if(end != s.c_str() + i) {
				auto ni = static_cast<size_t>(end - s.c_str());
				bool is_m = ni < s.size() && s[ni] == 'm';
				if(is_m) { val = meters_to_rssi(val); ++ni; }
				toks.push_back({ TokKind::Number, string(s.c_str() + i, end), val, is_m });
				i = ni; continue;
			}
		}

		++i;
	}
	toks.push_back({ TokKind::End, "" });
	return toks;
}

// ---- AST nodes ----

struct Value {
	bool is_const{ true };
	bool is_meters{ false };
	double constant{};
	pair<Tins::HWAddress<6>, Tins::HWAddress<6>> mac_pair;

	[[nodiscard]] double resolve(const RssiMatrix &m) const {
		if(is_const) return constant;
		double sum = 0;
		int n = 0;
		for(const auto &key: { mac_pair, { mac_pair.second, mac_pair.first } }) {
			if(auto it = m.find(key); it != m.end()) {
				sum += it->second;
				++n;
			}
		}
		return n > 0 ? sum / n : RSSI_NO_DATA;
	}

	[[nodiscard]] bool valid(const RssiMatrix &m) const {
		if(is_const) return true;
		auto has = [&](const auto &k) {
			const auto it = m.find(k);
			return it != m.end() && it->second > RSSI_NO_DATA;
		};
		return has(mac_pair) || has(make_pair(mac_pair.second, mac_pair.first));
	}

	[[nodiscard]] string to_str() const {
		if(is_const) {
			char buf[32];
			snprintf(buf, sizeof(buf), "%.0f", constant);
			return buf;
		}
		return "(" + mac_pair.first.to_string() + " <-> " + mac_pair.second.to_string() + ")";
	}
};

enum class Cmp { Lt, Le, Gt, Ge };
// distance and RSSI are inverse:
// closer = higher RSSI, so flip the operator
static constexpr Cmp flip_cmp(const Cmp c) {
	switch(c) {
		case Cmp::Lt: return Cmp::Gt;
		case Cmp::Le: return Cmp::Ge;
		case Cmp::Gt: return Cmp::Lt;
		case Cmp::Ge: return Cmp::Le;
	}
	return c;
}
static constexpr const char *cmp_str(const Cmp c) {
	switch(c) {
		case Cmp::Lt: return " < ";
		case Cmp::Le: return " <= ";
		case Cmp::Gt: return " > ";
		case Cmp::Ge: return " >= ";
	}
	return " ? ";
}

struct CmpExpr: Expr {
	Value lhs, rhs;
	Cmp op;
	string label;
	CmpExpr(Value l, Value r, const Cmp op_):
		lhs(std::move(l)),
		rhs(std::move(r)),
		op(op_),
		label(lhs.to_str() + cmp_str(op) + rhs.to_str()) {}
	[[nodiscard]] bool eval(const RssiMatrix &m) const override {
		const double l = lhs.resolve(m), r = rhs.resolve(m);
		switch(op) {
			case Cmp::Lt: return l < r;
			case Cmp::Le: return l <= r;
			case Cmp::Gt: return l > r;
			case Cmp::Ge: return l >= r;
		}
		return false;
	}
	[[nodiscard]] vector<pair<string, string>> to_colored_parts(const RssiMatrix &m) const override {
		if(!lhs.valid(m) || !rhs.valid(m)) return { { label + " (no data)", "#FFA500" } };
		return { { label, eval(m) ? "#00FF00" : "#555555" } };
	}
};

struct AndExpr: Expr {
	ExprPtr l, r;
	AndExpr(ExprPtr a, ExprPtr b):
		l(std::move(a)),
		r(std::move(b)) {}
	[[nodiscard]] bool eval(const RssiMatrix &m) const override { return l->eval(m) && r->eval(m); }
	[[nodiscard]] vector<pair<string, string>> to_colored_parts(const RssiMatrix &m) const override {
		auto parts = l->to_colored_parts(m);
		parts.emplace_back(" && ", eval(m) ? "#00FF00" : "#555555");
		auto rp = r->to_colored_parts(m);
		parts.insert(parts.end(), rp.begin(), rp.end());
		return parts;
	}
};

struct OrExpr: Expr {
	ExprPtr l, r;
	OrExpr(ExprPtr a, ExprPtr b):
		l(std::move(a)),
		r(std::move(b)) {}
	[[nodiscard]] bool eval(const RssiMatrix &m) const override { return l->eval(m) || r->eval(m); }
	[[nodiscard]] vector<pair<string, string>> to_colored_parts(const RssiMatrix &m) const override {
		auto parts = l->to_colored_parts(m);
		parts.emplace_back(" || ", eval(m) ? "#00FF00" : "#555555");
		auto rp = r->to_colored_parts(m);
		parts.insert(parts.end(), rp.begin(), rp.end());
		return parts;
	}
};

struct NotExpr: Expr {
	ExprPtr c;
	explicit NotExpr(ExprPtr x):
		c(std::move(x)) {}
	[[nodiscard]] bool eval(const RssiMatrix &m) const override { return !c->eval(m); }
	[[nodiscard]] vector<pair<string, string>> to_colored_parts(const RssiMatrix &m) const override {
		auto parts = vector<pair<string, string>>{ { "!", eval(m) ? "#00FF00" : "#555555" } };
		auto cp = c->to_colored_parts(m);
		parts.insert(parts.end(), cp.begin(), cp.end());
		return parts;
	}
};

// ---- Parser ----

struct Parser {
	const vector<Token> &toks;
	size_t pos{ 0 };

	[[nodiscard]] const Token &peek() const { return toks[pos]; }
	Token consume() { return toks[pos++]; }
	void expect(const TokKind k) {
		if(peek().kind != k) throw runtime_error("parse error near '" + peek().text + "'");
		consume();
	}

	Value parse_value() {
		if(peek().kind == TokKind::Number) {
			const Token t = consume();
			return { true, t.is_meters, t.num, {} };
		}
		if(peek().kind == TokKind::LParen) {
			consume();
			if(peek().kind != TokKind::Mac) throw runtime_error("expected MAC after '('");
			Tins::HWAddress<6> m1(consume().text);
			expect(TokKind::Arrow);
			if(peek().kind != TokKind::Mac) throw runtime_error("expected MAC after '<->'");
			Tins::HWAddress<6> m2(consume().text);
			expect(TokKind::RParen);
			return { false, false, 0.0, { m1, m2 } };
		}
		throw runtime_error("expected number or (mac <-> mac)");
	}

	Cmp consume_cmp() {
		switch(peek().kind) {
			case TokKind::Lt: consume(); return Cmp::Lt;
			case TokKind::Le: consume(); return Cmp::Le;
			case TokKind::Gt: consume(); return Cmp::Gt;
			case TokKind::Ge: consume(); return Cmp::Ge;
			default: throw runtime_error("expected '<', '<=', '>' or '>='");
		}
	}

	ExprPtr parse_atom() {
		auto build_cmp = [&](Value lhs) -> ExprPtr {
			Cmp cmp = consume_cmp();
			Value rhs = parse_value();
			if(lhs.is_meters || rhs.is_meters) cmp = flip_cmp(cmp);
			return make_unique<CmpExpr>(std::move(lhs), std::move(rhs), cmp);
		};
		if(peek().kind == TokKind::LParen) {
			if(pos + 1 < toks.size() && toks[pos + 1].kind == TokKind::Mac) return build_cmp(parse_value());
			consume();
			auto e = parse_expr();
			expect(TokKind::RParen);
			return e;
		}
		if(peek().kind == TokKind::Number) return build_cmp(parse_value());
		throw runtime_error("unexpected token '" + peek().text + "'");
	}

	ExprPtr parse_not() {
		if(peek().kind == TokKind::Not) {
			consume();
			return make_unique<NotExpr>(parse_not());
		}
		return parse_atom();
	}
	ExprPtr parse_and() {
		auto lhs = parse_not();
		while(peek().kind == TokKind::And) {
			consume();
			lhs = make_unique<AndExpr>(std::move(lhs), parse_not());
		}
		return lhs;
	}
	ExprPtr parse_expr() {
		auto lhs = parse_and();
		while(peek().kind == TokKind::Or) {
			consume();
			lhs = make_unique<OrExpr>(std::move(lhs), parse_and());
		}
		return lhs;
	}
};

// ---- Public API ----

ExprPtr parse_condition(const string &s) {
	log(wpa3_tester::LogLevel::INFO, "Parsing {}", s);
	if(s.empty()) return nullptr;
	const auto toks = tokenize(s);
	Parser p{ toks };
	return p.parse_expr();
}

void render_condition_status(FILE *pipe, const ExprPtr &expr, const RssiMatrix &m) {
	if(!expr) return;
	double x = 0.01, y = 0.88;
	int id = 100;
	for(const auto &[text, color]: expr->to_colored_parts(m)) {
		if(text == " && " || text == " || ") {
			y -= 0.05;
			x = 0.01;
			const char *op = (text == " && ") ? "&&" : "||";
			fprintf(pipe,
				"set label %d '%s' at screen %f,%f tc rgb '%s' font 'Monospace Bold,11' left\n",
				id++,
				op,
				x,
				y,
				color.c_str());
			x += 3 * 0.010;
		} else {
			fprintf(pipe,
				"set label %d '%s' at screen %f,%f tc rgb '%s' font 'Monospace Bold,11' left\n",
				id++,
				text.c_str(),
				x,
				y,
				color.c_str());
			x += static_cast<double>(text.size()) * 0.010;
		}
	}
}

string actor_names_to_mac(const string &actor_names_cond, const vector<wpa3_tester::ActorMap> &actors_maps) {
	string result = actor_names_cond;

	for(const auto &actors: actors_maps) {
		for(const auto &pair: actors) {
			const string &name = pair.first;

			if(!result.contains(name)) continue;
			string mac = Tins::HWAddress<6>(pair.second->get(wpa3_tester::SK::permanent_mac)).to_string();
			size_t pos = 0;
			while((pos = result.find(name, pos)) != string::npos) {
				result.replace(pos, name.length(), mac);
				pos += mac.length();
			}
		}
	}
	return result;
}