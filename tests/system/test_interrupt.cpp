#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <chrono>
#include <thread>
#include "inteprrupt.h"

using namespace std::chrono;

namespace{
// drains any pending byte left in the pipe and resets the interrupted flag,
// so tests don't leak state into each other via the shared globals.
void reset_interrupt_state(){
    g_interrupted.store(false);
    char buf;
    while(read(g_interrupt_pipe.read_fd, &buf, 1) > 0){}
}
}

TEST_CASE("interruptible_sleep - returns immediately if already interrupted"){
    reset_interrupt_state();
    g_interrupted.store(true);

    const auto start = steady_clock::now();
    interruptible_sleep(milliseconds(500));
    const auto elapsed = steady_clock::now() - start;

    CHECK_LT(elapsed, milliseconds(100));
    reset_interrupt_state();
}

TEST_CASE("interruptible_sleep - waits roughly the full duration when undisturbed"){
    reset_interrupt_state();

    const auto start = steady_clock::now();
    interruptible_sleep(milliseconds(100));
    const auto elapsed = duration_cast<milliseconds>(steady_clock::now() - start);

    CHECK_GE(elapsed.count(), 90);
    reset_interrupt_state();
}

TEST_CASE("interruptible_sleep - returns early when pipe is triggered mid-sleep"){
    reset_interrupt_state();

    std::thread trigger_thread([]{
        std::this_thread::sleep_for(milliseconds(20));
        g_interrupt_pipe.trigger();
    });

    const auto start = steady_clock::now();
    interruptible_sleep(milliseconds(2000));
    const auto elapsed = duration_cast<milliseconds>(steady_clock::now() - start);

    trigger_thread.join();
    CHECK_LT(elapsed.count(), 500);
    reset_interrupt_state();
}
