cmake_minimum_required(VERSION 3.20)
cmake_policy(SET CMP0167 NEW)
set(CMAKE_BUILD_TYPE Debug)
project(wpa3_tester VERSION 0.1.0 LANGUAGES CXX)

# optimization for compiling/ linking
execute_process(COMMAND lld --version RESULT_VARIABLE LLD_FOUND OUTPUT_QUIET ERROR_QUIET)
if(LLD_FOUND EQUAL 0)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=lld")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fuse-ld=lld")
    message(STATUS "Using LLD linker")
endif()

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
    message(STATUS "ccache found")
else()
    message(STATUS "ccache not found")
endif()

set(CMAKE_CXX_STANDARD 23)
if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(--coverage -O0 -g)
    add_link_options(--coverage)
endif()

# ----------- LIBRARIES -------------------

#libtins a libwifi mají oba target uninstall
set_property(GLOBAL PROPERTY ALLOW_DUPLICATE_CUSTOM_TARGETS TRUE)
set(CMAKE_WARN_DEPRECATED OFF CACHE BOOL "" FORCE)
set(CMAKE_ERROR_DEPRECATED OFF CACHE BOOL "" FORCE)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")

# Speed up compilation
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# Parallel linking with ninja
set_property(GLOBAL PROPERTY JOB_POOLS link_job_pool=2)
set(CMAKE_JOB_POOL_LINK link_job_pool)

include(FetchContent)

set(ARGPARSE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ARGPARSE_BUILD_SAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
        argparse
        GIT_REPOSITORY https://github.com/p-ranav/argparse.git
        GIT_TAG v3.2
        GIT_SHALLOW    TRUE
)

set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
        json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG         v3.12.0
        GIT_SHALLOW    TRUE
)

set(JSON_VALIDATOR_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(JSON_VALIDATOR_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
        json_schema_validator
        GIT_REPOSITORY https://github.com/pboettch/json-schema-validator.git
        GIT_TAG fb270d5a7dc570f60db50e2d5bced90ead7ba362
        GIT_SHALLOW FALSE
)

set(DOCTEST_WITH_TESTS OFF CACHE BOOL "" FORCE)
set(DOCTEST_WITH_MAIN_IN_STATIC_LIB OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
        doctest
        GIT_REPOSITORY https://github.com/doctest/doctest.git
        GIT_TAG        v2.4.11 # Use the latest version
)

set(LIBTINS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LIBTINS_ENABLE_CXX11 ON CACHE BOOL "" FORCE)
set(LIBTINS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LIBTINS_ENABLE_CXX11 ON CACHE BOOL "" FORCE)
set(LIBTINS_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
        libtins
        GIT_REPOSITORY https://github.com/Omelug/libtins.git
        GIT_TAG        master
        GIT_SUBMODULES ""
)

set(REPROCXX ON CACHE BOOL "" FORCE)
set(REPROC++ ON)
FetchContent_Declare(
        reproc
        GIT_REPOSITORY https://github.com/DaanDeMeyer/reproc
        GIT_TAG        v14.2.5
)
FetchContent_Declare(
        linux_headers_wifi
        URL https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/nl80211.h
        DOWNLOAD_NO_EXTRACT TRUE
)

set(SCIPLOT_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SCIPLOT_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SCIPLOT_EXPORT_TARGETS OFF CACHE BOOL "" FORCE)
set(SCIPLOT_BUILD_DOCS OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
        sciplot
        GIT_REPOSITORY https://github.com/sciplot/sciplot.git
        GIT_TAG        v0.3.1
)

# ------------------------------------------------

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(
        reproc
        libtins
        doctest
        argparse
        json
        json_schema_validator
        linux_headers_wifi
        sciplot
)

add_library(doctest_headers INTERFACE)
target_include_directories(doctest_headers INTERFACE "${doctest_SOURCE_DIR}" "${doctest_SOURCE_DIR}/doctest")


find_package(yaml-cpp REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL REQUIRED libnl-3.0 libnl-genl-3.0)
pkg_check_modules(LIBSSH REQUIRED libssh)
if(NOT LIBSSH_FOUND)
    message(FATAL_ERROR "libssh not found. Run: sudo apt install libssh-dev")
endif()

file(GLOB_RECURSE CORE_SOURCES
        "src/*.cpp"
        "src/*.h"
        "include/*.h"
)
message(STATUS "core sources: ${CORE_SOURCES}")

# Single library with Unity Build
add_library(wpa3_core STATIC ${CORE_SOURCES})

set(WIFI_HEADERS_DIR "${linux_headers_wifi_SOURCE_DIR}/..")

target_include_directories(wpa3_core PUBLIC
        include
        ${doctest_SOURCE_DIR}
        ${argparse_SOURCE_DIR}/include
        ${json_SOURCE_DIR}/include
        ${json_schema_validator_SOURCE_DIR}/src
        ${reproc_SOURCE_DIR}/reproc++/include
        ${LIBNL_INCLUDE_DIRS}
        ${LIBSSH_INCLUDE_DIRS}
        ${WIFI_HEADERS_DIR}
        ${sciplot_SOURCE_DIR}
)

target_link_libraries(wpa3_core PUBLIC
        doctest_headers
        yaml-cpp
        nlohmann_json_schema_validator
        nlohmann_json::nlohmann_json
        argparse::argparse
        doctest
        tins
        reproc++
        nl-3 nl-genl-3
        ${LIBNL_LIBRARIES}
        ${LIBSSH_LIBRARIES}
)

add_executable(${PROJECT_NAME} "../wpa3_test/main.cpp")
target_link_libraries(${PROJECT_NAME} PRIVATE wpa3_core)

set_target_properties(${PROJECT_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
target_compile_definitions(wpa3_core PUBLIC PROJECT_ROOT_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

target_precompile_headers(wpa3_core PUBLIC
        <vector>
        <string>
        <map>
        <unordered_map>
        <set>
        <memory>
        <optional>
        <variant>
        <tuple>
        <functional>
        <algorithm>
        <numeric>
        <ranges>
        <fstream>
        <iostream>
        <filesystem>
        <chrono>
        <thread>
        <mutex>
        <atomic>
        <stdexcept>
        <cassert>
        <cstdint>
        <cstdlib>
        <cstring>
        <csignal>
        # Third-party
        <nlohmann/json.hpp>
        <nlohmann/json-schema.hpp>
        <yaml-cpp/yaml.h>
        <tins/tins.h>
        <argparse/argparse.hpp>
        <reproc++/reproc.hpp>
        <sciplot/sciplot.hpp>
)
enable_testing()
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../tests" "${CMAKE_BINARY_DIR}/tests")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../tests_manual" "${CMAKE_BINARY_DIR}/tests_manual")
include(CPack)
