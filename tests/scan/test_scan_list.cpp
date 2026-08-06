#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include "scan_test_helpers.h"

using namespace std;
using namespace wpa3_tester;

TEST_SUITE("list_external_entities") {

	TEST_CASE("empty channel list throws before any hardware access") {
		CHECK_THROWS(RunStatus::list_external_entities("lo", 1, {}));
	}

	//not other invalid status
	TEST_CASE("nonexistent interface throws at pcap_create") {
		CHECK_THROWS(RunStatus::list_external_entities("nonexistent_xyz", 1, {6}));
	}
}

