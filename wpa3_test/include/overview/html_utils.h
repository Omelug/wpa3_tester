#pragma once
#include <functional>
#include <string>
#include <type_traits>
#include <vector>

#include "html_guard.h"

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
            [f = std::forward<Func>(func)](const EntryType& e) {
                f(e);
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

    void render(const std::string& table_class = "aggregate") const {
        hg_ << "        <table class=\"" << table_class << "\">\n"
            << "            <thead><tr>";
        for (const auto& col : columns_) hg_ << "<th>" << col.header << "</th>";
        hg_ << "</tr></thead>\n            <tbody>\n";

        for (const auto& entry : entries_) {
            hg_ << "                <tr>\n";
            for (const auto& col : columns_) {
                hg_ << "                    <td>";
                col.evaluator(entry);
                hg_ << "</td>\n";
            }
            hg_ << "                </tr>\n";
        }
        hg_ << "            </tbody>\n        </table>\n";
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
	void build(BuilderFunc&& builder) {
		builder(Helper{*this});
	}

private:
    struct Column {
        std::string header;
        std::function<void(const EntryType&)> evaluator;
    };

    wpa3_tester::overview::HtmlGuard& hg_;
    std::vector<EntryType> entries_;
    std::vector<Column> columns_;
};