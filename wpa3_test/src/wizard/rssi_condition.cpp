#include "wizard/rssi_condition.h"

#include <algorithm>
#include <cstdio>
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
    Value lhs, rhs;
    bool lt;
    string orig_text;

    CmpExpr(Value l, Value r, const bool lt_)
        : lhs(std::move(l)), rhs(std::move(r)), lt(lt_) {

        auto val_to_str = [](const Value& v) {
            if (v.is_const) {
                char buf[32];
                snprintf(buf, sizeof(buf), "%.0f", v.constant);
                return string(buf);
            }
            return "(" + v.mac_pair.first + " <-> " + v.mac_pair.second + ")";
        };

        orig_text = val_to_str(lhs) + (lt ? " < " : " > ") + val_to_str(rhs);
    }

    bool eval(const RssiMatrix& m) const override {
        return lt ? lhs.resolve(m) < rhs.resolve(m) : lhs.resolve(m) > rhs.resolve(m);
    }

    vector<pair<string, string>> to_colored_parts(const RssiMatrix& m) const override {
        bool is_true = eval(m);
        string color = is_true ? "#00FF00" : "#555555";
        return { {orig_text, color} };
    }
};

struct AndExpr : Expr {
    ExprPtr l, r;
    AndExpr(ExprPtr a, ExprPtr b) : l(move(a)), r(move(b)) {}

    bool eval(const RssiMatrix& m) const override {
        return l->eval(m) && r->eval(m);
    }

    vector<pair<string, string>> to_colored_parts(const RssiMatrix& m) const override {
        auto left_parts = l->to_colored_parts(m);
        auto right_parts = r->to_colored_parts(m);

        string op_color = eval(m) ? "#00FF00" : "#555555";

        left_parts.push_back({ " && ", op_color });
        left_parts.insert(left_parts.end(), right_parts.begin(), right_parts.end());
        return left_parts;
    }
};

struct OrExpr : Expr {
    ExprPtr l, r;
    OrExpr(ExprPtr a, ExprPtr b) : l(move(a)), r(move(b)) {}

    bool eval(const RssiMatrix& m) const override {
        return l->eval(m) || r->eval(m);
    }

    vector<pair<string, string>> to_colored_parts(const RssiMatrix& m) const override {
        auto left_parts = l->to_colored_parts(m);
        auto right_parts = r->to_colored_parts(m);

        string op_color = eval(m) ? "#00FF00" : "#555555";

        left_parts.push_back({ " || ", op_color });
        left_parts.insert(left_parts.end(), right_parts.begin(), right_parts.end());
        return left_parts;
    }
};

struct NotExpr : Expr {
    ExprPtr c;
    explicit NotExpr(ExprPtr x) : c(move(x)) {}

    bool eval(const RssiMatrix& m) const override {
        return !c->eval(m);
    }

    vector<pair<string, string>> to_colored_parts(const RssiMatrix& m) const override {
        string op_color = eval(m) ? "#00FF00" : "#555555";

        vector<pair<string, string>> parts = { { "!", op_color } };
        auto child_parts = c->to_colored_parts(m);
        parts.insert(parts.end(), child_parts.begin(), child_parts.end());
        return parts;
    }
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

void render_condition_status(FILE* pipe, const ExprPtr& root_expr, const RssiMatrix& matrix) {
    if (!root_expr) return;

    auto parts = root_expr->to_colored_parts(matrix);

    double x_pos = 0.05; // Začátek na levé straně obrazovky (5 % šířky)
    int label_id = 100;

    for (const auto& [text, color] : parts) {
        constexpr double y_pos = 0.03; // Dolní okraj (3 % výšky)
        fprintf(pipe, "set label %d '%s' at screen %f, %f tc rgb '%s' font 'Monospace,10' left\n",
                label_id++,
                text.c_str(),
                x_pos,
                y_pos,
                color.c_str());

        // Posuneme X pozici pro další podřetězec podle jeho délky
        x_pos += static_cast<double>(text.length()) * 0.009;
    }
}

// ---- Public API ----
ExprPtr parse_condition(const string& s) {
    if (s.empty()) return nullptr;
    const auto toks = tokenize(s);
    Parser p{toks};
    return p.parse_expr();
}
