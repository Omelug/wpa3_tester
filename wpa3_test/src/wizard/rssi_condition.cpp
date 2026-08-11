#include "wizard/rssi_condition.h"

#include <algorithm>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace std;

static string normalize_mac(string mac) {
    ranges::transform(mac, mac.begin(), ::tolower);
    return mac;
}

// ---- Tokenizer ----

enum class TokKind { LParen, RParen, And, Or, Not, Arrow, Lt, Gt, Number, Mac, End };

struct Token { TokKind kind; string text; double num{}; };

static vector<Token> tokenize(const string& s) {
    vector<Token> toks;
    size_t i = 0;
    while (i < s.size()) {
        if (isspace(static_cast<unsigned char>(s[i]))) { ++i; continue; }
        const char c = s[i];

        if (c == '(') { toks.push_back({TokKind::LParen, "("}); ++i; continue; }
        if (c == ')') { toks.push_back({TokKind::RParen, ")"}); ++i; continue; }
        if (c == '!') { toks.push_back({TokKind::Not,    "!"}); ++i; continue; }
        if (c == '&' && i+1 < s.size() && s[i+1] == '&') { toks.push_back({TokKind::And, "&&"}); i+=2; continue; }
        if (c == '|' && i+1 < s.size() && s[i+1] == '|') { toks.push_back({TokKind::Or,  "||"}); i+=2; continue; }
        if (c == '<') {
            if (i+2 < s.size() && s[i+1] == '-' && s[i+2] == '>') { toks.push_back({TokKind::Arrow, "<->"}); i+=3; continue; }
            toks.push_back({TokKind::Lt, "<"}); ++i; continue;
        }
        if (c == '>') { toks.push_back({TokKind::Gt, ">"}); ++i; continue; }

        // MAC: exactly xx:xx:xx:xx:xx:xx (17 chars)
        if (i + 17 <= s.size()) {
            bool is_mac = true;
            for (int k = 0; k < 6 && is_mac; ++k) {
                is_mac = isxdigit(static_cast<unsigned char>(s[i + k*3]))
                      && isxdigit(static_cast<unsigned char>(s[i + k*3 + 1]))
                      && (k == 5 || s[i + k*3 + 2] == ':');
            }
            if (is_mac) { toks.push_back({TokKind::Mac, s.substr(i, 17)}); i += 17; continue; }
        }

        // Number (including negative)
        if (c == '-' || isdigit(static_cast<unsigned char>(c))) {
            char* end;
			const double val = strtod(s.c_str() + i, &end);
            if (end != s.c_str() + i) {
                toks.push_back({TokKind::Number, string(s.c_str()+i, static_cast<const char*>(end)), val});
                i = static_cast<size_t>(end - s.c_str()); continue;
            }
        }

        ++i;  // skip unknown char
    }
    toks.push_back({TokKind::End, ""});
    return toks;
}

// ---- AST nodes ----

struct Value {
    bool is_const{true};
    double constant{};
    pair<string,string> mac_pair;  // both normalized

    double resolve(const RssiMatrix& m) const {
        if (is_const) return constant;
        // <-> is symmetric: average both directions when both present
        double sum = 0; int n = 0;
        for (const auto& key : {mac_pair, {mac_pair.second, mac_pair.first}}) {
            auto it = m.find(key);
            if (it != m.end()) { sum += it->second; ++n; }
        }
        return n > 0 ? sum / n : -90.0;
    }
};

struct CmpExpr : Expr {
    Value lhs, rhs; bool lt;
    CmpExpr(const Value &l, const Value &r, const bool lt_) : lhs(l), rhs(r), lt(lt_) {}
    bool eval(const RssiMatrix& m) const override {
        return lt ? lhs.resolve(m) < rhs.resolve(m) : lhs.resolve(m) > rhs.resolve(m);
    }
};
struct AndExpr : Expr {
    ExprPtr l, r;
    AndExpr(ExprPtr a, ExprPtr b) : l(move(a)), r(move(b)) {}
    bool eval(const RssiMatrix& m) const override { return l->eval(m) && r->eval(m); }
};
struct OrExpr : Expr {
    ExprPtr l, r;
    OrExpr(ExprPtr a, ExprPtr b) : l(move(a)), r(move(b)) {}
    bool eval(const RssiMatrix& m) const override { return l->eval(m) || r->eval(m); }
};
struct NotExpr : Expr {
    ExprPtr c;
    explicit NotExpr(ExprPtr x) : c(move(x)) {}
    bool eval(const RssiMatrix& m) const override { return !c->eval(m); }
};

// ---- Parser ----

struct Parser {
    const vector<Token>& toks;
    size_t pos{0};

    const Token& peek() const { return toks[pos]; }
    Token consume() { return toks[pos++]; }
    void expect(const TokKind k) {
        if (peek().kind != k) throw runtime_error("parse error near '" + peek().text + "'");
        consume();
    }

    Value parse_value() {
        if (peek().kind == TokKind::Number)
            return {true, consume().num, {}};
        if (peek().kind == TokKind::LParen) {
            consume();
            if (peek().kind != TokKind::Mac) throw runtime_error("expected MAC after '('");
            string m1 = normalize_mac(consume().text);
            expect(TokKind::Arrow);
            if (peek().kind != TokKind::Mac) throw runtime_error("expected MAC after '<->'");
            string m2 = normalize_mac(consume().text);
            expect(TokKind::RParen);
            return {false, 0.0, {m1, m2}};
        }
        throw runtime_error("expected number or (mac <-> mac)");
    }

    ExprPtr parse_atom() {
        if (peek().kind == TokKind::LParen) {
            // Distinguish "(mac <-> mac) op value" from "(expr)"
            if (pos + 1 < toks.size() && toks[pos+1].kind == TokKind::Mac) {
                Value lhs = parse_value();
                const bool lt = (peek().kind == TokKind::Lt);
                if (peek().kind != TokKind::Lt && peek().kind != TokKind::Gt)
                    throw runtime_error("expected '<' or '>'");
                consume();
                return make_unique<CmpExpr>(lhs, parse_value(), lt);
            }
            consume();
            auto e = parse_expr();
            expect(TokKind::RParen);
            return e;
        }
        if (peek().kind == TokKind::Number) {
            Value lhs = parse_value();
            const bool lt = (peek().kind == TokKind::Lt);
            if (peek().kind != TokKind::Lt && peek().kind != TokKind::Gt)
                throw runtime_error("expected '<' or '>'");
            consume();
            return make_unique<CmpExpr>(lhs, parse_value(), lt);
        }
        throw runtime_error("unexpected token '" + peek().text + "'");
    }

    ExprPtr parse_not() {
        if (peek().kind == TokKind::Not) { consume(); return make_unique<NotExpr>(parse_not()); }
        return parse_atom();
    }

    ExprPtr parse_and() {
        auto lhs = parse_not();
        while (peek().kind == TokKind::And) { consume(); lhs = make_unique<AndExpr>(move(lhs), parse_not()); }
        return lhs;
    }

    ExprPtr parse_expr() {
        auto lhs = parse_and();
        while (peek().kind == TokKind::Or) { consume(); lhs = make_unique<OrExpr>(move(lhs), parse_and()); }
        return lhs;
    }
};

// ---- Public API ----

ExprPtr parse_condition(const string& s) {
    if (s.empty()) return nullptr;
	const auto toks = tokenize(s);
    Parser p{toks};
    return p.parse_expr();
}
