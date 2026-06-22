#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include "logger/report.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester::report;

struct ReportFixture {
	path dir;
	explicit ReportFixture(const string &name) : dir(temp_directory_path() / name) {
		create_directories(dir);
	}
	string read_report() const {
		ifstream f(dir / "report.md");
		return {istreambuf_iterator<char>(f), istreambuf_iterator<char>()};
	}
	~ReportFixture() { remove_all(dir); }
};

TEST_CASE("ReportGuard - creates report.md") {
	ReportFixture fx("rg_creates");
	{ ReportGuard rg(fx.dir); }
	CHECK(exists(fx.dir / "report.md"));
}

TEST_CASE("ReportGuard - operator bool") {
	ReportFixture fx("rg_bool");
	ReportGuard rg(fx.dir);
	CHECK(static_cast<bool>(rg));
}

TEST_CASE("ReportGuard - string: non-empty written as-is") {
	ReportFixture fx("rg_str");
	{ ReportGuard rg(fx.dir); rg << string("hello"); }
	CHECK_EQ(fx.read_report(), "hello");
}

TEST_CASE("ReportGuard - string: empty written as '?'") {
	ReportFixture fx("rg_str_empty");
	{ ReportGuard rg(fx.dir); rg << string(""); }
	CHECK_EQ(fx.read_report(), "?");
}

TEST_CASE("ReportGuard - bool true -> 'yes'") {
	ReportFixture fx("rg_bool_true");
	{ ReportGuard rg(fx.dir); rg << true; }
	CHECK_EQ(fx.read_report(), "yes");
}

TEST_CASE("ReportGuard - bool false -> 'no'") {
	ReportFixture fx("rg_bool_false");
	{ ReportGuard rg(fx.dir); rg << false; }
	CHECK_EQ(fx.read_report(), "no");
}

TEST_CASE("ReportGuard - optional<bool> true -> 'yes'") {
	ReportFixture fx("rg_opt_true");
	{ ReportGuard rg(fx.dir); rg << optional<bool>{true}; }
	CHECK_EQ(fx.read_report(), "yes");
}

TEST_CASE("ReportGuard - optional<bool> false -> 'no'") {
	ReportFixture fx("rg_opt_false");
	{ ReportGuard rg(fx.dir); rg << optional<bool>{false}; }
	CHECK_EQ(fx.read_report(), "no");
}

TEST_CASE("ReportGuard - optional<bool> nullopt -> 'N/A'") {
	ReportFixture fx("rg_opt_null");
	{ ReportGuard rg(fx.dir); rg << optional<bool>{}; }
	CHECK_EQ(fx.read_report(), "N/A");
}

TEST_CASE("ReportGuard - path relativized to run_dir") {
	ReportFixture fx("rg_path");
	{ ReportGuard rg(fx.dir); rg << (fx.dir / "subdir" / "file.txt"); }
	CHECK_EQ(fx.read_report(), string("subdir/file.txt"));
}

TEST_CASE("ReportGuard - path already relative unchanged") {
	ReportFixture fx("rg_path_rel");
	{ ReportGuard rg(fx.dir); rg << path("subdir/file.txt"); }
	CHECK_EQ(fx.read_report(), string("subdir/file.txt"));
}

TEST_CASE("ReportGuard - chaining preserves overloads") {
	ReportFixture fx("rg_chain");
	{
		ReportGuard rg(fx.dir);
		rg << string("val=") << true << string(" opt=") << optional<bool>{} << string(" path=") << (fx.dir / "x.txt");
	}
	CHECK_EQ(fx.read_report(), "val=yes opt=N/A path=x.txt");
}

TEST_CASE("ReportGuard - integer passthrough") {
	ReportFixture fx("rg_int");
	{ ReportGuard rg(fx.dir); rg << 42; }
	CHECK_EQ(fx.read_report(), "42");
}

TEST_CASE("link - with run_dir returns relative markdown link") {
	ReportFixture fx("link_rel");
	const path file = fx.dir / "sub" / "report.md";
	create_directories(file.parent_path());
	ofstream(file).close();
	CHECK_EQ(link("label", file, fx.dir), "[label](sub/report.md)");
}

TEST_CASE("link - without run_dir returns absolute markdown link") {
	ReportFixture fx("link_abs");
	const path file = fx.dir / "report.md";
	ofstream(file).close();
	CHECK_EQ(link("label", file), "[label]("+file.string()+")");
}
