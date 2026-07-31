#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <tins/hw_address.h>
#include "overview/html_guard.h"

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
	{ HtmlGuard hg(fx.dir); hg << optional{true}; }
	CHECK_EQ(fx.read_index(), "yes");
}

TEST_CASE("HtmlGuard - optional<bool> false -> 'no'") {
	HtmlFixture fx("hg_opt_false");
	{ HtmlGuard hg(fx.dir); hg << optional{false}; }
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

TEST_CASE("device() - no device page -> returns MAC string") {
	HtmlFixture fx("dev_none");
	const auto mac = Tins::HWAddress<6>("aa:bb:cc:dd:ee:ff");
	CHECK_EQ(device(mac, fx.dir), string("aa:bb:cc:dd:ee:ff"));
}

TEST_CASE("device() - device page at root -> returns relative link") {
	HtmlFixture fx("dev_root");
	const string mac_str = "aa:bb:cc:dd:ee:ff";
	const auto mac = Tins::HWAddress<6>(mac_str);
	const path dev_dir = fx.dir / "devices" / mac_str;
	create_directories(dev_dir);
	{ ofstream(dev_dir / "index.html") << "device"; }
	CHECK_EQ(device(mac, fx.dir),
	         "<a href=\"devices/aa:bb:cc:dd:ee:ff/index.html\">aa:bb:cc:dd:ee:ff</a>");
}

TEST_CASE("device() - device page found via ancestor -> link uses correct depth") {
	HtmlFixture fx("dev_nested");
	const string mac_str = "bb:cc:dd:ee:ff:00";
	const auto mac = Tins::HWAddress<6>(mac_str);
	const path dev_dir = fx.dir / "devices" / mac_str;
	create_directories(dev_dir);
	{ ofstream(dev_dir / "index.html") << "device"; }
	const path nested = fx.dir / "attacks" / "dos_soft" / "channel_switch";
	CHECK_EQ(device(mac, nested),
	         "<a href=\"../../../devices/bb:cc:dd:ee:ff:00/index.html\">bb:cc:dd:ee:ff:00</a>");
}

using wpa3_tester::described_bool;
using wpa3_tester::described_str;

static const string TOOLTIP_HDR =
	R"(<span class="tooltip-content"><table><tr><th>Value</th><th>Source</th></tr>)";
static const string TOOLTIP_FTR = "</table></span></span>";

TEST_CASE("described_bool - empty -> '?'") {
	HtmlFixture fx("db_empty");
	{ HtmlGuard hg(fx.dir); hg << described_bool{}; }
	CHECK_EQ(fx.read_index(), "?");
}

TEST_CASE("described_bool - single true entry") {
	HtmlFixture fx("db_true");
	described_bool db; db += {true, "src"};
	{ HtmlGuard hg(fx.dir); hg << db; }
	CHECK_EQ(fx.read_index(),
	         R"(<span class="has-tooltip">yes)" + TOOLTIP_HDR +
	         "<tr><td>yes</td><td>src</td></tr>" + TOOLTIP_FTR);
}

TEST_CASE("described_bool - single false entry") {
	HtmlFixture fx("db_false");
	described_bool db; db += {false, "src"};
	{ HtmlGuard hg(fx.dir); hg << db; }
	CHECK_EQ(fx.read_index(),
	         R"(<span class="has-tooltip">no)" + TOOLTIP_HDR +
	         "<tr><td>no</td><td>src</td></tr>" + TOOLTIP_FTR);
}


TEST_CASE("described_bool - multiple entries: last shown, all in table") {
	HtmlFixture fx("db_multi");
	described_bool db; db += {false, "s1"}; db += {false, "s2"};
	{ HtmlGuard hg(fx.dir); hg << db; }
	CHECK_EQ(fx.read_index(),
	         R"(<span class="has-tooltip">no)" + TOOLTIP_HDR +
	         "<tr><td>no</td><td>s1</td></tr>"
	         "<tr><td>no</td><td>s2</td></tr>" + TOOLTIP_FTR);
}

TEST_CASE("described_str - empty -> '?'") {
	HtmlFixture fx("ds_empty");
	{ HtmlGuard hg(fx.dir); hg << described_str{}; }
	CHECK_EQ(fx.read_index(), "?");
}

TEST_CASE("described_str - single non-empty string entry") {
	HtmlFixture fx("ds_str");
	described_str ds; ds += {"hello", "src"};
	{ HtmlGuard hg(fx.dir); hg << ds; }
	CHECK_EQ(fx.read_index(),
	         R"(<span class="has-tooltip">hello)" + TOOLTIP_HDR +
	         "<tr><td>hello</td><td>src</td></tr>" + TOOLTIP_FTR);
}


TEST_CASE("described_str - multiple entries: last shown, all in table") {
	HtmlFixture fx("ds_multi");
	described_str ds; ds += {"first", "s1"}; ds += {"second", "s2"};
	{ HtmlGuard hg(fx.dir); hg << ds; }
	CHECK_EQ(fx.read_index(),
	         R"(<span class="has-tooltip"><strong style="color:red">second</strong>)" + TOOLTIP_HDR +
	         "<tr><td>v</td><td>s1</td></tr>"
	         "<tr><td>second</td><td>s2</td></tr>" + TOOLTIP_FTR);
}
