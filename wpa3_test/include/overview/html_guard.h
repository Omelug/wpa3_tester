#pragma once
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

#include "default.h"
#include "overview/described.h"
#include "system/utils.h"

inline std::ostream &operator<<(std::ostream &os, std::optional<bool> val){
	return os << (val ? (*val ? "yes" : "no") : "N/A");
}

namespace wpa3_tester::overview {

// RAII guard: opens index.html in page_dir, exposes operator<<, closes on destruction.
struct HtmlGuard {
	explicit HtmlGuard(const std::filesystem::path &page_dir)
		: stream_(page_dir / "index.html"), page_dir_(page_dir) {}
	~HtmlGuard(){ stream_.close(); set_public_perms(page_dir_ / "index.html");}
	HtmlGuard(const HtmlGuard &) = delete;
	HtmlGuard &operator=(const HtmlGuard &) = delete;

	explicit operator bool() const { return stream_.is_open(); }

	HtmlGuard &operator<<(const std::filesystem::path &p){
		const auto rel = p.is_absolute() ? p.lexically_relative(page_dir_) : p;
		stream_ << rel.string(); return *this;
	}
	HtmlGuard &operator<<(const bool val){
		stream_ << (val ? "yes" : "no"); return *this;
	}
	HtmlGuard &operator<<(const std::pair<bool, std::string> &val){
		stream_ << (val.first ? "yes" : "no");
		if(!val.second.empty()) stream_ << " (" << val.second << ')';
		return *this;
	}
	HtmlGuard &operator<<(const std::pair<std::optional<bool>, std::string> &val){
		if(!val.first.has_value()) stream_ << '?';
		else stream_ << (*val.first ? "yes" : "no");
		if(!val.second.empty()) stream_ << " (" << val.second << ')';
		return *this;
	}
	HtmlGuard &operator<<(const std::optional<bool> val){
		stream_ << (val ? (*val ? "yes" : "no") : "N/A"); return *this;
	}
	HtmlGuard &operator<<(const std::string &val){
		if(val.empty()) stream_ << '?'; else stream_ << val; return *this;
	}
	HtmlGuard &operator<<(const std::pair<std::string, std::string> &val){
		if(val.first.empty()) stream_ << '?';
		else{
			stream_ << val.first;
			if(!val.second.empty()) stream_ << " (" << val.second << ')';
		}
		return *this;
	}
	HtmlGuard &operator<<(const std::optional<std::string> &val){
		stream_ << (val.has_value() ? val.value() : "N/A"); return *this;
	}
	HtmlGuard &operator<<(const described_bool &val){
		if(val.empty()){ stream_ << '?'; return *this; }
		const auto &last = val.last();
		const bool conflict = std::ranges::any_of(val.pairs, [&](const auto &p){ return p.value != val.pairs.front().value; });

		stream_ << R"(<span class="has-tooltip">)";
		if(conflict) stream_ << R"(<strong style="color:red">)";
		stream_ << last.value;
		if(conflict) stream_ << "</strong>";
		stream_ << R"(<span class="tooltip-content"><table><tr><th>Value</th><th>Source</th></tr>)";
		for(const auto &[v, d] : val.pairs)
			stream_ << "<tr><td>" << v << "</td><td>" << d << "</td></tr>";
		stream_ << "</table></span></span>";

		return *this;
	}
	HtmlGuard &operator<<(const described_str &val){
		if(val.empty()){ stream_ << '?'; return *this; }
		const auto &last = val.last();
		const bool conflict = std::ranges::any_of(val.pairs, [&](const auto &p){ return p.value != val.pairs.front().value; });

		stream_ << R"(<span class="has-tooltip">)";
		if(conflict) stream_ << R"(<strong style="color:red">)";
		if(last.value.empty()) stream_ << '?'; else stream_ << last.value;
		if(conflict) stream_ << "</strong>";
		stream_ << R"(<span class="tooltip-content"><table><tr><th>Value</th><th>Source</th></tr>)";
		for(const auto &[v, d] : val.pairs)
			stream_ << "<tr><td>" << v << "</td><td>" << d << "</td></tr>";
		stream_ << "</table></span></span>";
		return *this;
	}
	template<typename T>
	requires (!std::same_as<std::remove_cvref_t<T>, bool> &&
	          !std::same_as<std::remove_cvref_t<T>, std::optional<bool>> &&
	          !std::same_as<std::remove_cvref_t<T>, std::string> &&
	          !std::same_as<std::remove_cvref_t<T>, std::pair<bool, std::string>> &&
	          !std::same_as<std::remove_cvref_t<T>, std::pair<std::optional<bool>, std::string>> &&
	          !std::same_as<std::remove_cvref_t<T>, std::pair<std::string, std::string>> &&
	          !std::same_as<std::remove_cvref_t<T>, std::filesystem::path> &&
	          !std::same_as<std::remove_cvref_t<T>, described_bool> &&
	          !std::same_as<std::remove_cvref_t<T>, described_str>)
	HtmlGuard &operator<<(T &&val){ stream_ << std::forward<T>(val); return *this; }

private:
	std::ofstream stream_;
	std::filesystem::path page_dir_;
};

inline std::string device(const Tins::HWAddress<6> mac, const std::filesystem::path &page_dir){
	auto mac_str = mac.to_string();
	auto root = page_dir;
	while(!root.empty() && root != root.parent_path()){
		const auto dev_page = root / "devices" / mac_str / "index.html";
		if(std::filesystem::exists(dev_page))
			return "<a href=\"" + dev_page.lexically_relative(page_dir).string() + "\">" + mac_str + "</a>";
		root = root.parent_path();
	}
	return mac_str;
}

// Returns test name as HTML, linked to report.md if it exists.
inline std::string test_name_cell(const std::filesystem::path &test_folder,
                                  const std::string &name,
                                  const std::filesystem::path &page_dir) {
	const auto report = test_folder / REPORT_NAME;
	if (!std::filesystem::exists(report)) return name;
	return "<a href=\"" + report.lexically_relative(page_dir).string() + "\">" + name + "</a>";
}

}
