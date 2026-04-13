set(CMAKE_POLICY_DEFAULT_CMP0000 OLD)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
set(CMAKE_POLICY_DEFAULT_CMP0167 NEW)

set_property(GLOBAL PROPERTY ALLOW_DUPLICATE_CUSTOM_TARGETS TRUE)
set(CMAKE_WARN_DEPRECATED  OFF CACHE BOOL "" FORCE)
set(CMAKE_ERROR_DEPRECATED OFF CACHE BOOL "" FORCE)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set_property(GLOBAL PROPERTY JOB_POOLS link_job_pool=2)
set(CMAKE_JOB_POOL_LINK link_job_pool)

include(FetchContent)

set(ARGPARSE_BUILD_TESTS   OFF CACHE BOOL "" FORCE)
set(ARGPARSE_BUILD_SAMPLES OFF CACHE BOOL "" FORCE)
set(JSON_BuildTests                  OFF CACHE BOOL "" FORCE)
set(JSON_VALIDATOR_BUILD_TESTS       OFF CACHE BOOL "" FORCE)
set(JSON_VALIDATOR_BUILD_EXAMPLES    OFF CACHE BOOL "" FORCE)
set(DOCTEST_WITH_TESTS               OFF CACHE BOOL "" FORCE)
set(DOCTEST_WITH_MAIN_IN_STATIC_LIB  OFF CACHE BOOL "" FORCE)
set(LIBTINS_BUILD_TESTS      OFF CACHE BOOL "" FORCE)
set(LIBTINS_BUILD_EXAMPLES   OFF CACHE BOOL "" FORCE)
set(LIBTINS_ENABLE_INSTALL   OFF CACHE BOOL "" FORCE)
set(LIBTINS_ENABLE_CXX11     ON  CACHE BOOL "" FORCE)
set(LIBTINS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(LIBTINS_ENABLE_ACK_TRACKER OFF CACHE BOOL "" FORCE)
set(LIBTINS_ENABLE_WPA2      OFF CACHE BOOL "" FORCE)
set(LIBTINS_ENABLE_DOT11     ON  CACHE BOOL "" FORCE)
set(LIBTINS_ENABLE_PCAP      ON  CACHE BOOL "" FORCE)
set(REPROC_STATIC               ON CACHE BOOL "" FORCE)
set(REPROC_CXX                 ON  CACHE BOOL "" FORCE)
set(REPROC++        ON CACHE BOOL "" FORCE)
set(BUILD_TESTING            OFF CACHE BOOL "" FORCE)

FetchContent_Declare(argparse
        GIT_REPOSITORY https://github.com/p-ranav/argparse.git
        GIT_TAG        v3.2
        GIT_SHALLOW    TRUE
)
FetchContent_Declare(json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        v3.12.0
        GIT_SHALLOW    TRUE
)
FetchContent_Declare(json_schema_validator
        GIT_REPOSITORY https://github.com/pboettch/json-schema-validator.git
        GIT_TAG        fb270d5a7dc570f60db50e2d5bced90ead7ba362
        GIT_SHALLOW    FALSE
        OVERRIDE_FIND_PACKAGE
)
FetchContent_Declare(doctest
        GIT_REPOSITORY https://github.com/doctest/doctest.git
        GIT_TAG        v2.4.11
        GIT_SHALLOW    TRUE
        OVERRIDE_FIND_PACKAGE
)
FetchContent_Declare(libtins
        GIT_REPOSITORY https://github.com/mfontanini/libtins.git
        GIT_TAG       master
        GIT_SHALLOW    TRUE
        GIT_SUBMODULES ""
        PATCH_COMMAND sed -i "s/#pragma once/#pragma once\\n#include <cstdint>/"
        ${CMAKE_BINARY_DIR}/_deps/libtins-src/include/tins/ip_address.h
        OVERRIDE_FIND_PACKAGE
)
FetchContent_Declare(reproc
        GIT_REPOSITORY https://github.com/DaanDeMeyer/reproc
        GIT_TAG        v14.2.5
        GIT_SHALLOW    TRUE
        GIT_SUBMODULES ""
        OVERRIDE_FIND_PACKAGE
)
FetchContent_Declare(linux_headers_wifi
        URL https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/nl80211.h
        DOWNLOAD_NO_EXTRACT TRUE
)

FetchContent_MakeAvailable(
        reproc libtins doctest argparse
        json json_schema_validator linux_headers_wifi
)

add_library(doctest_headers INTERFACE)
target_include_directories(doctest_headers INTERFACE
        "${doctest_SOURCE_DIR}"
        "${doctest_SOURCE_DIR}/doctest"
)

find_package(yaml-cpp REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL  REQUIRED libnl-3.0 libnl-genl-3.0)
pkg_check_modules(LIBSSH REQUIRED libssh)
if(NOT LIBSSH_FOUND)
    message(FATAL_ERROR "libssh not found. Run: sudo apt install libssh-dev")
endif()