#pragma once
#include <filesystem>
#include <fstream>

namespace wpa3_tester::overview {

inline std::filesystem::file_time_type newest_mtime(const std::filesystem::path &dir) {
	auto t = std::filesystem::file_time_type::min();
	if(!std::filesystem::exists(dir)) return t;
	std::error_code ec;
	for(const auto &e: std::filesystem::recursive_directory_iterator(
				dir, std::filesystem::directory_options::skip_permission_denied)) {
		if(const auto mt = std::filesystem::last_write_time(e, ec); !ec && mt > t) t = mt;
	}
	return t;
}

// Returns true if data_dir is unchanged since the stamp file was last touched
inline bool data_unchanged(const std::filesystem::path &page_dir, const std::filesystem::path &data_dir) {
	if(newest_mtime(data_dir) == std::filesystem::file_time_type::min()) {
		std::filesystem::remove_all(page_dir);
		return true;
	}
	const auto stamp = page_dir / ".data_stamp";
	std::error_code ec;
	const auto stamp_mtime = std::filesystem::last_write_time(stamp, ec);
	if(ec) return false;
	if(!std::filesystem::exists(page_dir / "index.html")) return false;
	return newest_mtime(data_dir) <= stamp_mtime;
}

// Just touch the stamp file — no value stored, no epoch issues
inline void update_data_stamp(const std::filesystem::path &page_dir, const std::filesystem::path & /*data_dir*/) {
	std::ofstream(page_dir / ".data_stamp");
}

}
