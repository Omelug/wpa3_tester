#pragma once
#include <filesystem>
#include <fstream>
#include <sys/stat.h>

namespace wpa3_tester::overview {

inline time_t newest_mtime(const std::filesystem::path &dir) {
	time_t t = 0;
	if(!std::filesystem::exists(dir)) return t;
	for(const auto &e: std::filesystem::recursive_directory_iterator(
			dir, std::filesystem::directory_options::skip_permission_denied)) {
		struct stat st{};
		if(stat(e.path().c_str(), &st) == 0 && st.st_mtime > t) t = st.st_mtime;
	}
	return t;
}

inline time_t read_data_stamp(const std::filesystem::path &page_dir) {
	std::ifstream f(page_dir / ".data_stamp");
	if(!f) return 0;
	time_t t = 0;
	f >> t;
	return t;
}

inline void write_data_stamp(const std::filesystem::path &page_dir, const std::filesystem::path &data_dir) {
	std::ofstream f(page_dir / ".data_stamp");
	f << newest_mtime(data_dir);
}

// for pages with two independent data sources (example: devices: dev_data + ap_info)
inline void write_data_stamp(const std::filesystem::path &page_dir,
	const std::filesystem::path &d1, const std::filesystem::path &d2) {
	std::ofstream f(page_dir / ".data_stamp");
	f << std::max(newest_mtime(d1), newest_mtime(d2));
}

static bool data_unchanged_impl(const std::filesystem::path &page_dir, const time_t newest) {
	if(newest == 0) return false;
	const time_t stamp = read_data_stamp(page_dir);
	if(stamp != 0) return newest == stamp;  // clock-skew-safe once stamp written
	// no stamp yet: fall back to index.html mtime
	struct stat st{};
	if(stat((page_dir / "index.html").c_str(), &st) != 0) return false;
	return newest <= st.st_mtime;
}

inline bool data_unchanged(const std::filesystem::path &page_dir, const std::filesystem::path &data_dir) {
	return data_unchanged_impl(page_dir, newest_mtime(data_dir));
}

inline bool data_unchanged(const std::filesystem::path &page_dir,
	const std::filesystem::path &d1, const std::filesystem::path &d2) {
	return data_unchanged_impl(page_dir, std::max(newest_mtime(d1), newest_mtime(d2)));
}

}
