#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>

#include "logger/report.h"
#include "root_dir_helper.h"
#include "system/utils.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester;
using namespace wpa3_tester::report;

namespace {
path device_root() { return root_dir().parent_path() / DATA_DIR / DEVICES_DIR; }
}

TEST_CASE("device - no device dir returns plain MAC") {
	const test_helpers::IsolatedRootDir isolated("report_device_1");
	const Tins::HWAddress<6> mac("aa:bb:cc:dd:ee:01");
	CHECK_EQ(device(mac), string("aa:bb:cc:dd:ee:01"));
}

TEST_CASE("device - existing device dir returns markdown link") {
	const test_helpers::IsolatedRootDir isolated("report_device_2");
	const Tins::HWAddress<6> mac("aa:bb:cc:dd:ee:02");
	const path dev_dir = device_root() / mac.to_string();
	create_directories(dev_dir);

	const string result = device(mac);
	CHECK_EQ(result, "[aa:bb:cc:dd:ee:02](" + dev_dir.string() + ")");
}

TEST_CASE("link - constructs Link with given text and path") {
	const Link l = link("label", path("some/file.md"));
	CHECK_EQ(l.text, "label");
	CHECK_EQ(l.link_path, path("some/file.md"));
}
