#pragma once
#include <algorithm>
#include <functional>
#include <string>
#include <type_traits>
#include <vector>
#include "html_guard.h"

constexpr int MINIMAL_PREFIX = 5;

template <typename EntryType>
class HtmlPathTable {
public:
    explicit HtmlPathTable(wpa3_tester::overview::HtmlGuard& hg, const std::vector<EntryType>& entries)
        : hg_(hg), entries_(entries) {}

    void add_column(std::string header, std::function<void(const EntryType&)> eval) {
        columns_.push_back({std::move(header), std::move(eval)});
    }

    // add with entry function
    template <typename Func>
    void add_column(std::string header, Func&& func)
        requires std::is_invocable_v<Func, const EntryType&> {
        columns_.push_back({
            std::move(header),
            [f = std::forward<Func>(func), this](const EntryType& e) {
                hg_ << f(e);
            }
        });
    }

    // add entry param directly
    template <typename T>
    void add_column(std::string header, T EntryType::*member) {
        columns_.push_back({
            std::move(header),
            [member, this](const EntryType& e) {
                hg_ << (e.*member);
            }
        });
    }

    // Like add_column but renders the <th> with class="rotated" (vertical writing-mode via CSS).
    void add_rotated_column(std::string header, std::function<void(const EntryType&)> eval) {
        columns_.push_back({std::move(header), std::move(eval), true});
    }

    template <typename Func>
    void add_rotated_column(std::string header, Func&& func)
        requires std::is_invocable_v<Func, const EntryType&> {
        columns_.push_back({
            std::move(header),
            [f = std::forward<Func>(func), this](const EntryType& e) { hg_ << f(e); },
            true
        });
    }

    template <typename T>
    void add_rotated_column(std::string header, T EntryType::*member) {
        columns_.push_back({
            std::move(header),
            [member, this](const EntryType& e) { hg_ << (e.*member); },
            true
        });
    }

private:
    struct Column {
        std::string header;
        std::function<void(const EntryType&)> evaluator{};
        bool rotated = false;
    };

    wpa3_tester::overview::HtmlGuard& hg_;
    std::vector<EntryType> entries_;
    std::vector<Column> columns_;

    std::string capture_evaluator_output(const Column& col, const EntryType& entry) const {
        std::ostringstream oss;
        std::ostream& stream = hg_.stream_;
        auto* old_buf = stream.rdbuf(oss.rdbuf());
        col.evaluator(entry);
        stream.rdbuf(old_buf);

        return oss.str();
    }

	static std::string find_common_prefix(const std::vector<std::string>& strings){
		if (strings.empty()) return "";

		const std::string& first = strings[0];
		size_t len = 0;

		for (; len < first.size(); ++len) {
			for (const auto& str : strings) {
				if (len >= str.size() || str[len] != first[len]) {
					return len >= MINIMAL_PREFIX ? first.substr(0, len) : "";
				}
			}
		}

		return len >= MINIMAL_PREFIX ? first : "";
	}

    [[nodiscard]] bool is_prefix_requested(const std::string& header, const std::vector<std::string>& prefix_columns) const {
        return std::find(prefix_columns.begin(), prefix_columns.end(), header) != prefix_columns.end();
    }

    std::string compute_column_prefix(const Column& col) const {
        std::vector<std::string> values;
        values.reserve(entries_.size());
        for (const auto& entry : entries_) {
            values.push_back(capture_evaluator_output(col, entry));
        }
        return find_common_prefix(values);
    }
    [[nodiscard]] std::vector<std::string> prepare_prefixes(const std::vector<std::string>& prefix_columns) const {
        std::vector<std::string> prefixes(columns_.size());
        for (size_t i = 0; i < columns_.size(); ++i) {
            if (is_prefix_requested(columns_[i].header, prefix_columns)) {
                prefixes[i] = compute_column_prefix(columns_[i]);
            }
        }
        return prefixes;
    }
    void render_header(const std::vector<std::string>& prefixes) const {
        hg_ << "            <thead><tr>";
        for (size_t i = 0; i < columns_.size(); ++i) {
            const char* th_open = columns_[i].rotated ? "<th class=\"rotated\">" : "<th>";
            if (!prefixes[i].empty()) {
                hg_ << th_open << prefixes[i] << "*</th>";
            } else {
                hg_ << th_open << columns_[i].header << "</th>";
            }
        }
        hg_ << "</tr></thead>\n";
    }
    void render_body(const std::vector<std::string>& prefixes) const {
        hg_ << "            <tbody>\n";
        for (const auto& entry : entries_) {
            hg_ << "                <tr>\n";
            for (size_t i = 0; i < columns_.size(); ++i) {
                hg_ << "                    <td>";
                std::string value = capture_evaluator_output(columns_[i], entry);
                const std::string& prefix = prefixes[i];

                if (!prefix.empty() && value.rfind(prefix, 0) == 0) {
                    hg_ << value.substr(prefix.length());
                } else {
                    hg_ << value;
                }
                hg_ << "</td>\n";
            }
            hg_ << "                </tr>\n";
        }
        hg_ << "            </tbody>\n";
    }
public:
    void render(const std::vector<std::string>& prefix_columns = {}, const std::string& table_class = "aggregate") const {
        std::vector<std::string> prefixes = prepare_prefixes(prefix_columns);

        hg_ << "        <table class=\"" << table_class << "\">\n";
        render_header(prefixes);
        render_body(prefixes);
        hg_ << "        </table>\n";
    }

    struct Helper {
        HtmlPathTable& self;

        void operator()(std::string name, std::function<void(const EntryType&)> eval) {
            self.add_column(std::move(name), std::move(eval));
        }

        template <typename Func>
        requires std::is_invocable_v<const EntryType&>
        void operator()(std::string name, Func&& func) {
            self.add_column(std::move(name), std::forward<Func>(func));
        }

        template <typename T>
        void operator()(std::string name, T EntryType::*member) {
            self.add_column(std::move(name), member);
        }
    };

    template <typename BuilderFunc>
    HtmlPathTable* build(BuilderFunc&& builder) {
        builder(Helper{*this});
        return this;
    }

};