#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <atomic>
#include <mutex>
#include <vector>
#include <string>
#include "system/ProcessManager.h"

using namespace wpa3_tester;
using namespace std;

// ------------ before_stop
TEST_CASE (
"before_stop: callback "
)
 {
    ProcessManager pm;
    pm.run_dummy("proc");

    atomic called{false};
    pm.before_stop("proc", [&called] { called = true; });
    pm.stop("proc");

    CHECK(called.load());
}

TEST_CASE (
"before_stop: callback "
)
 {
    ProcessManager pm;
    pm.run_dummy("proc");

    vector<string> order;
    mutex mtx;

    pm.before_stop("proc", [&] {
        lock_guard lk(mtx);
        order.push_back("before");
    });
    pm.after_stop("proc", [&] {
        lock_guard lk(mtx);
        order.push_back("after");
    });

    pm.stop("proc");

    REQUIRE_EQ(order.size(), 2);
    CHECK_EQ(order[0], "before");
    CHECK_EQ(order[1], "after");
}

TEST_CASE (
"before_stop: invalid dont crash"
)
 {
    ProcessManager pm;
    CHECK_NOTHROW(pm.before_stop("invalid", [] {}));
}

TEST_CASE (
"before_stop: throw exception in callback, stop() emds"
)
 {
    ProcessManager pm;
    pm.run_dummy("proc");

    pm.before_stop("proc", [] { throw runtime_error("callback error"); });

    CHECK_NOTHROW(pm.stop("proc"));
}

TEST_CASE (
"before_stop: overwrite of callback"
)
 {
    ProcessManager pm;
    pm.run_dummy("proc");

    atomic<int> first{0}, second{0};
    pm.before_stop("proc", [&first]  { ++first;  });
    pm.before_stop("proc", [&second] { ++second; });

    pm.stop("proc");

    CHECK_EQ(first.load(), 0); // overwrite
    CHECK_EQ(second.load(), 1); // called
}

TEST_CASE (
"after_stop: stop()"
)
 {
    ProcessManager pm;
    pm.run_dummy("proc");

    atomic called{false};
    pm.after_stop("proc", [&called] { called = true; });
    pm.stop("proc");

    CHECK(called.load());
}

// ------------- after_stop
TEST_CASE (
"after_stop: invalid proces dont crash"
)
 {
    ProcessManager pm;
    CHECK_NOTHROW(pm.after_stop("invalid", [] {}));
}

TEST_CASE (
"after_stop: throw exception in callback, stop() emds"
)
 {
    ProcessManager pm;
    pm.run_dummy("proc");

    pm.after_stop("proc", [] { throw runtime_error("callback error"); });

    CHECK_NOTHROW(pm.stop("proc"));
}

TEST_CASE (
"after_stop: overwrite"
)
 {
    ProcessManager pm;
    pm.run_dummy("proc");

    atomic<int> first{0}, second{0};
    pm.after_stop("proc", [&first]  { ++first;  });
    pm.after_stop("proc", [&second] { ++second; });

    pm.stop("proc");

    CHECK_EQ(first.load(), 0);
    CHECK_EQ(second.load(), 1);
}

//  stop_all

TEST_CASE (
"stop_all: both callbacks"
)
 {
    ProcessManager pm;
    pm.run_dummy("p1");
    pm.run_dummy("p2");

    atomic<int> before_count{0}, after_count{0};

    for (const auto& name : {"p1", "p2"}) {
        pm.before_stop(name, [&before_count] { ++before_count; });
        pm.after_stop (name, [&after_count]  { ++after_count;  });
    }

    pm.stop_all();

    CHECK_EQ(before_count.load(), 2);
    CHECK_EQ(after_count.load(), 2);
}