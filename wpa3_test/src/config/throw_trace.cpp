#include <stacktrace>
#include <unordered_map>
#include "logger/error_log.h"

namespace wpa3_tester {
    namespace {
        struct ThrowEntry {
            std::stacktrace trace;
            void (*orig_dest)(void*);
        };
        thread_local std::unordered_map<const void*, ThrowEntry> g_traces;
        const std::stacktrace g_empty;

        void cleanup_dest(void* obj) {
            const auto it = g_traces.find(obj);
            if (it == g_traces.end()) return;
            const auto orig = it->second.orig_dest;
            g_traces.erase(it);
            if (orig) orig(obj);
        }
    }

    const std::stacktrace& throw_trace_for(const void* ex_ptr) {
        const auto it = g_traces.find(ex_ptr);
        return it != g_traces.end() ? it->second.trace : g_empty;
    }
}

extern "C" void __real___cxa_throw(void*, void*, void(*)(void*));

extern "C" [[noreturn]] void __wrap___cxa_throw(void* obj, void* tinfo, void(*dest)(void*)) {
    wpa3_tester::g_traces[obj] = { std::stacktrace::current(1), dest };
    __real___cxa_throw(obj, tinfo, wpa3_tester::cleanup_dest);
    __builtin_unreachable();
}
