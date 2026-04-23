#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "logger/log.h"
#include "system/hw_capabilities.h"
#include "system/runtime_checks.h"

using namespace std;
using namespace wpa3_tester;

namespace wpa3_tester{
//test with some mockup
/*TEST_CASE("Runtime injection check - manual test with interface") {
        // Set the interface name to test (change this to your actual interface)
        const string TEST_INTERFACE = "wlan1";  // CHANGE THIS to your monitor mode interface

        log(LogLevel::INFO, "Testing injection capability on interface: %s", TEST_INTERFACE.c_str());

        const bool injection_supported = check_injection_runtime(TEST_INTERFACE);

        if (injection_supported) {
            log(LogLevel::INFO, "Interface %s SUPPORTS injection", TEST_INTERFACE.c_str());
        } else {
            log(LogLevel::WARNING, "Interface %s does NOT support injection (or test failed)",
                TEST_INTERFACE.c_str());
        }

        // Log the result - test will pass regardless, this is for manual verification
        INFO("Injection check result for ", TEST_INTERFACE, ": ", injection_supported);

        // You can uncomment this if you want the test to fail when injection is not supported:
        // CHECK(injection_supported);
    }*/

/*TEST_CASE("Runtime injection check - test with non-existent interface") {
        const string FAKE_INTERFACE = "fake_wlan999";
        log(LogLevel::INFO, "Testing injection with non-existent interface: %s", FAKE_INTERFACE.c_str());

        const bool result = check_injection_runtime(FAKE_INTERFACE);
        CHECK_FALSE(result); // Should return false for non-existent interface
    }*/
}