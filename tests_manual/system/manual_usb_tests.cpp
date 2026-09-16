#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <cstdio>
#include <filesystem>
#include <string>
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

TEST_CASE("usb_bus_reset - devices remain in sysfs after reset") {
    const auto ifaces = collect_all_usb_devices();
    if(ifaces.empty()) {
        log(LogLevel::INFO, "No USB WiFi adapters found, skipping");
        return;
    }

    log(LogLevel::INFO, "Will USB-reset {} device(s):", ifaces.size());
    for(const auto &i: ifaces)
        log(LogLevel::INFO, "  {} (driver={})", i.iface_id, i.driver_name);

    // capture dmesg line count before so we can show only new lines after reset
    size_t dmesg_before = 0;
    if(FILE *p = popen("dmesg | wc -l", "r")) {
        fscanf(p, "%zu", &dmesg_before);
        pclose(p);
    }

    REQUIRE_NOTHROW(usb_bus_reset(ifaces));

    // sysfs path must survive bus reset - device keeps USB address, only protocol state resets
    for(const auto &i: ifaces)
        CHECK(filesystem::exists(i.dev_path));

    // informational: show new dmesg lines confirming kernel processed the reset
    if(dmesg_before > 0) {
        const string cmd = "dmesg | tail -n +" + to_string(dmesg_before + 1) + " | grep -i 'reset\\|disconnect'";
        if(FILE *p = popen(cmd.c_str(), "r")) {
            char buf[512];
            while(fgets(buf, sizeof(buf), p)) {
                string s(buf);
                if(!s.empty() && s.back() == '\n') s.pop_back();
                log(LogLevel::INFO, "dmesg: {}", s);
            }
            pclose(p);
        }
    }
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
