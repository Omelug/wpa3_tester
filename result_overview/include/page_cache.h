#pragma once
#include <filesystem>
#include <sys/stat.h>

namespace wpa3_tester::overview {

inline time_t newest_ctime(const std::filesystem::path &dir) {
	time_t t = 0;
	if(!std::filesystem::exists(dir)) return t;
	for(const auto &e: std::filesystem::recursive_directory_iterator(
				dir, std::filesystem::directory_options::skip_permission_denied)) {
		struct stat st{};
		if(stat(e.path().c_str(), &st) == 0 && st.st_ctime > t) t = st.st_ctime;
	}
	return t;
}

inline bool data_unchanged(const std::filesystem::path &page_dir, const std::filesystem::path &data_dir) {
	const time_t newest = newest_ctime(data_dir);
	if(newest == 0) return false;
	struct stat st{};
	if(stat((page_dir / "index.html").c_str(), &st) != 0) return false;
	return newest <= st.st_mtime;
}

}
