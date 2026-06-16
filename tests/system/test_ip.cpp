#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "logger/error_log.h"
#include "system/ip.h"

using namespace wpa3_tester;

TEST_CASE("get_ip - loopback returns 127.0.0.1"){
    CHECK_EQ(ip::get_ip("lo"), "127.0.0.1");
}

TEST_CASE("get_ip - nonexistent interface throws run_err"){
    CHECK_THROWS_AS(ip::get_ip("nonexistent_iface_xyz"), run_err);
}

TEST_CASE("resolve_host - localhost resolves to 127.0.0.1"){
    CHECK_EQ(ip::resolve_host("localhost"), "127.0.0.1");
}

TEST_CASE("resolve_host - invalid hostname throws run_err"){
    CHECK_THROWS_AS(ip::resolve_host("this.does.not.exist.invalid"), run_err);
}