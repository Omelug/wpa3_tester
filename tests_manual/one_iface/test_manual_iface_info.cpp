#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <chrono>
#include <doctest.h>
#include <thread>
#include "../manual_test_core/manual_test_wizards.h"
#include "config/RunStatus.h"
#include "ex_program/external_actors/openwrt/OpenWrtConn.h"

using namespace std;
using namespace wpa3_tester;
using namespace filesystem;
using namespace std::chrono;
using namespace manual_tests;

TEST_CASE ("Check"){
	get_iface_wizard();
}