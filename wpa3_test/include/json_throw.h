#pragma once
#include <stacktrace>
#include <stdexcept>
#include <string>
#include <chrono>
#include <format>
#include <cxxabi.h>
#include <cstdlib>

#define JSON_THROW_USER(ex) \
    throw std::runtime_error(std::string((ex).what()) + "\n" + std::to_string(std::stacktrace::current()))

inline std::string tins_error_str(const std::exception& ex, std::stacktrace trace) {
    auto now = std::chrono::zoned_time{std::chrono::current_zone(), std::chrono::system_clock::now()};
    int status{};
    char* raw = abi::__cxa_demangle(typeid(ex).name(), nullptr, nullptr, &status);
    std::string type = (status == 0 && raw) ? raw : typeid(ex).name();
    std::free(raw);
    return std::format("=== Error occurred at {:%FT%T%Ez} ===\nException type: {}\nMessage: {}\n{}",
        now, type, ex.what(), std::to_string(trace));
}

#define TINS_RETHROW(ex) throw std::runtime_error(tins_error_str((ex), std::stacktrace::current()))
