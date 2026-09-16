#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include "logger/log.h"
#include "setup/usb_helper.h"

using namespace std;
using namespace wpa3_tester;

TEST_CASE("collect_all_usb_devices - list detected adapters") {
    const auto ifaces = collect_all_usb_devices();
    log(LogLevel::INFO, "Found {} USB WiFi interface(s)", ifaces.size());

    for(const auto &i : ifaces) {
        log(LogLevel::INFO, "  id={} driver={} path={}", i.iface_id, i.driver_name, i.dev_path.string());
        CHECK_FALSE(i.iface_id.empty());
        CHECK(filesystem::exists(i.dev_path));
        // iface_id must contain '-' (USB topology, e.g. "1-1.4")
        CHECK_NE(i.iface_id.find('-'), string::npos);
    }
    // Not asserting count - machine may have zero USB WiFi adapters
}

TEST_CASE("reset_usb_ifaces - power-cycles adapters and rebinds drivers") {
    const auto before = collect_all_usb_devices();
    log(LogLevel::INFO, "Before reset: {} USB devices(s)", before.size());

    REQUIRE_NOTHROW(reset_usb_ifaces());

    const auto after = collect_all_usb_devices();
    log(LogLevel::INFO, "After reset: {} USB WiFi interface(s)", after.size());

    // All adapters that were present before should be back
    CHECK_GE(after.size(), before.size());
}
