cmake_minimum_required(VERSION 3.15)
project(wpa3_tester LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")

include(FetchContent)

FetchContent_Declare(
        argparse
        GIT_REPOSITORY https://github.com/p-ranav/argparse.git
        GIT_TAG v3.0
)

FetchContent_Declare(
        json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.12.0
)

FetchContent_Declare(
        json_schema_validator
        GIT_REPOSITORY https://github.com/pboettch/json-schema-validator.git
        GIT_TAG fb270d5a7dc570f60db50e2d5bced90ead7ba362
        GIT_SHALLOW FALSE
)

set(JSON_VALIDATOR_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(JSON_VALIDATOR_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(argparse json json_schema_validator)

find_package(yaml-cpp REQUIRED)

file(GLOB_RECURSE SOURCES
        "*.cpp"
        "src/*.cpp"
        "include/*.h"
        "../../wpa3_test_suite/src/*.cpp"
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
        include
        ${argparse_SOURCE_DIR}/include
        ${json_SOURCE_DIR}/include
        ${json_schema_validator_SOURCE_DIR}/src
)

target_link_libraries(${PROJECT_NAME} PRIVATE
        yaml-cpp
        nlohmann_json_schema_validator
        nlohmann_json::nlohmann_json
        argparse::argparse
)

set_target_properties(${PROJECT_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
include(CPack)