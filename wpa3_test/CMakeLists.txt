cmake_minimum_required(VERSION 3.5)
project(wpa3_tester VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
#libtins a libwifi mají oba target uninstall
set_property(GLOBAL PROPERTY ALLOW_DUPLICATE_CUSTOM_TARGETS TRUE)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")

include(FetchContent)

set(ARGPARSE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ARGPARSE_BUILD_SAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
        argparse
        GIT_REPOSITORY https://github.com/p-ranav/argparse.git
        GIT_TAG v3.2
)

set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
        json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG         v3.12.0
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
)

if(doctest_SOURCE_DIR)
        include_directories(${doctest_SOURCE_DIR})
        include_directories(${doctest_SOURCE_DIR}/doctest)
endif()

find_package(yaml-cpp REQUIRED)

file(GLOB_RECURSE SOURCES
        "src/*.cpp"
        "src/*.h"
        "include/*.h"
        "../../wpa3_test_suite/src/*.cpp"
)
list(APPEND SOURCES "../wpa3_test/main.cpp")


find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL REQUIRED libnl-3.0 libnl-genl-3.0)
add_executable(${PROJECT_NAME} ${SOURCES})

set(WIFI_HEADERS_DIR "${linux_headers_wifi_SOURCE_DIR}/..")

target_include_directories(${PROJECT_NAME} PRIVATE
        include
        ${doctest_SOURCE_DIR}
        ${argparse_SOURCE_DIR}/include
        ${json_SOURCE_DIR}/include
        ${json_schema_validator_SOURCE_DIR}/src
        ${reproc_SOURCE_DIR}/reproc++/include
        ${LIBNL_INCLUDE_DIRS}
        ${WIFI_HEADERS_DIR}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
        yaml-cpp
        nlohmann_json_schema_validator
        nlohmann_json::nlohmann_json
        argparse::argparse
        doctest
        tins
        reproc++
        nl-3 nl-genl-3
        ${LIBNL_LIBRARIES}
)

set_target_properties(${PROJECT_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
include(CPack)
target_compile_definitions(wpa3_tester PRIVATE PROJECT_ROOT_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
