set(CMAKE_MINIMUM_REQUIRED_VERSION 3.10)
project(wpa3_tester LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")

include(FetchContent)

FetchContent_Declare(
        argparse
        GIT_REPOSITORY https://github.com/p-ranav/argparse.git
        GIT_TAG v3.2
)

FetchContent_Declare(
        json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG         v3.12.0
)

FetchContent_Declare(
        json_schema_validator
        GIT_REPOSITORY https://github.com/pboettch/json-schema-validator.git
        GIT_TAG fb270d5a7dc570f60db50e2d5bced90ead7ba362
        GIT_SHALLOW FALSE
)
FetchContent_Declare(
        doctest
        GIT_REPOSITORY https://github.com/doctest/doctest.git
        GIT_TAG        v2.4.11 # Use the latest version
)

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ARGPARSE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ARGPARSE_BUILD_SAMPLES OFF CACHE BOOL "" FORCE)
set(JSON_VALIDATOR_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(JSON_VALIDATOR_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(DOCTEST_WITH_TESTS OFF CACHE BOOL "" FORCE)
set(DOCTEST_WITH_MAIN_IN_STATIC_LIB OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(doctest argparse json json_schema_validator)

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

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
        include
        ${doctest_SOURCE_DIR}
        ${argparse_SOURCE_DIR}/include
        ${json_SOURCE_DIR}/include
        ${json_schema_validator_SOURCE_DIR}/src
)

target_link_libraries(${PROJECT_NAME} PRIVATE
        yaml-cpp
        nlohmann_json_schema_validator
        nlohmann_json::nlohmann_json
        argparse::argparse
        doctest
)

set_target_properties(${PROJECT_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
include(CPack)
target_compile_definitions(wpa3_tester PRIVATE PROJECT_ROOT_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
