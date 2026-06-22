#pragma once
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
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
	HtmlGuard &operator<<(const std::optional<bool> val){
		stream_ << (val ? (*val ? "yes" : "no") : "N/A"); return *this;
	}
	HtmlGuard &operator<<(const std::string &val){
		if(val.empty()) stream_ << '?'; else stream_ << val; return *this;
	}
	template<typename T>
	requires (!std::same_as<std::remove_cvref_t<T>, bool> &&
	          !std::same_as<std::remove_cvref_t<T>, std::optional<bool>> &&
	          !std::same_as<std::remove_cvref_t<T>, std::string> &&
	          !std::same_as<std::remove_cvref_t<T>, std::filesystem::path>)
	HtmlGuard &operator<<(T &&val){ stream_ << std::forward<T>(val); return *this; }

private:
	std::ofstream stream_;
	std::filesystem::path page_dir_;
};

inline std::string device(Tins::HWAddress<6> mac, std::filesystem::path page_dir){
	//FIXME
	return mac;
}

}
