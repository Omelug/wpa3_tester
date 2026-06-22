#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include "html_guard.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester::overview;

struct HtmlFixture {
	path dir;
	explicit HtmlFixture(const string &name) : dir(temp_directory_path() / name) {
		create_directories(dir);
	}
	string read_index() const {
		ifstream f(dir / "index.html");
		return {istreambuf_iterator(f), istreambuf_iterator<char>()};
	}
	~HtmlFixture() { remove_all(dir); }
};

TEST_CASE("HtmlGuard - creates index.html") {
	HtmlFixture fx("hg_creates");
	{ HtmlGuard hg(fx.dir); }
	CHECK(exists(fx.dir / "index.html"));
}

TEST_CASE("HtmlGuard - operator bool") {
	HtmlFixture fx("hg_bool");
	HtmlGuard hg(fx.dir);
	CHECK(static_cast<bool>(hg));
}

TEST_CASE("HtmlGuard - string: non-empty written as-is") {
	HtmlFixture fx("hg_str");
	{ HtmlGuard hg(fx.dir); hg << string("hello"); }
	CHECK_EQ(fx.read_index(), "hello");
}

TEST_CASE("HtmlGuard - string: empty written as '?'") {
	HtmlFixture fx("hg_str_empty");
	{ HtmlGuard hg(fx.dir); hg << string(""); }
	CHECK_EQ(fx.read_index(), "?");
}

TEST_CASE("HtmlGuard - bool true -> 'yes'") {
	HtmlFixture fx("hg_bool_true");
	{ HtmlGuard hg(fx.dir); hg << true; }
	CHECK_EQ(fx.read_index(), "yes");
}

TEST_CASE("HtmlGuard - bool false -> 'no'") {
	HtmlFixture fx("hg_bool_false");
	{ HtmlGuard hg(fx.dir); hg << false; }
	CHECK_EQ(fx.read_index(), "no");
}

TEST_CASE("HtmlGuard - optional<bool> true -> 'yes'") {
	HtmlFixture fx("hg_opt_true");
	{ HtmlGuard hg(fx.dir); hg << optional<bool>{true}; }
	CHECK_EQ(fx.read_index(), "yes");
}

TEST_CASE("HtmlGuard - optional<bool> false -> 'no'") {
	HtmlFixture fx("hg_opt_false");
	{ HtmlGuard hg(fx.dir); hg << optional<bool>{false}; }
	CHECK_EQ(fx.read_index(), "no");
}

TEST_CASE("HtmlGuard - optional<bool> nullopt -> 'N/A'") {
	HtmlFixture fx("hg_opt_null");
	{ HtmlGuard hg(fx.dir); hg << optional<bool>{}; }
	CHECK_EQ(fx.read_index(), "N/A");
}

TEST_CASE("HtmlGuard - path relativized to page_dir") {
	HtmlFixture fx("hg_path");
	{ HtmlGuard hg(fx.dir); hg << (fx.dir / "subdir" / "file.html"); }
	CHECK_EQ(fx.read_index(), string("subdir/file.html"));
}

TEST_CASE("HtmlGuard - path already relative unchanged") {
	HtmlFixture fx("hg_path_rel");
	{ HtmlGuard hg(fx.dir); hg << path("subdir/file.html"); }
	CHECK_EQ(fx.read_index(), string("subdir/file.html"));
}

TEST_CASE("HtmlGuard - chaining preserves overloads") {
	HtmlFixture fx("hg_chain");
	{
		HtmlGuard hg(fx.dir);
		hg << string("val=") << true << string(" opt=") << optional<bool>{} << string(" path=") << (fx.dir / "x.html");
	}
	CHECK_EQ(fx.read_index(), "val=yes opt=N/A path=x.html");
}

TEST_CASE("HtmlGuard - integer passthrough") {
	HtmlFixture fx("hg_int");
	{ HtmlGuard hg(fx.dir); hg << 42; }
	CHECK_EQ(fx.read_index(), "42");
}
