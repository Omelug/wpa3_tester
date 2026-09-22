#pragma once
#include <stacktrace>
#include <stdexcept>
#include <string>
#define JSON_THROW_USER(ex) \
    throw std::runtime_error(std::string((ex).what()) + "\n" + std::to_string(std::stacktrace::current()))
