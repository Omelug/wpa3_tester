#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>
#include "page_cache.h"

using namespace wpa3_tester::overview;
using namespace std::filesystem;

TEST_CASE("data_unchanged") {
	const path tmp = temp_directory_path() / "test_page_cache";
	remove_all(tmp);
	const path page_dir = tmp / "page";
	const path data_dir = tmp / "data";
	create_directories(page_dir);
	create_directories(data_dir);

	SUBCASE("no data -> false") { CHECK_FALSE(data_unchanged(page_dir, data_dir)); }

	SUBCASE("data but no index.html -> false") {
		std::ofstream(data_dir / "result.json") << "{}";
		CHECK_FALSE(data_unchanged(page_dir, data_dir));
	}

	// fallback path (no stamp): compares newest mtime against index.html mtime
	SUBCASE("index.html newer than data -> true") {
		std::ofstream(data_dir / "result.json") << "{}";
		std::ofstream(page_dir / "index.html") << "<html/>";
		last_write_time(page_dir / "index.html", file_time_type::clock::now() + std::chrono::seconds(5));
		CHECK(data_unchanged(page_dir, data_dir));
	}

	SUBCASE("index.html older than data -> false") {
		std::ofstream(page_dir / "index.html") << "<html/>";
		last_write_time(page_dir / "index.html", file_time_type::clock::now() - std::chrono::seconds(5));
		std::ofstream(data_dir / "result.json") << "{}";
		CHECK_FALSE(data_unchanged(page_dir, data_dir));
	}

	// stamp path: compares newest mtime against stored stamp (clock-skew-safe)
	SUBCASE("stamp matches -> true") {
		std::ofstream(data_dir / "result.json") << "{}";
		write_data_stamp(page_dir, data_dir);
		CHECK(data_unchanged(page_dir, data_dir));
	}

	SUBCASE("stamp stale after new data -> false") {
		std::ofstream(data_dir / "result.json") << "{}";
		write_data_stamp(page_dir, data_dir);
		std::ofstream(data_dir / "new.json") << "{}";
		last_write_time(data_dir / "new.json", file_time_type::clock::now() + std::chrono::seconds(5));
		CHECK_FALSE(data_unchanged(page_dir, data_dir));
	}

	remove_all(tmp);
}
