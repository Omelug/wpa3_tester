add_library(wpa3_deps INTERFACE)
target_link_libraries(wpa3_deps INTERFACE radiotap_lib)


target_include_directories(wpa3_deps INTERFACE
        ${linux_headers_wifi_SOURCE_DIR}
)

target_include_directories(wpa3_deps INTERFACE
        ${CMAKE_CURRENT_BINARY_DIR}/awk_scripts
        include
        ${linux_headers_wifi_SOURCE_DIR}
        ${doctest_SOURCE_DIR}
        ${argparse_SOURCE_DIR}/include
        ${json_SOURCE_DIR}/include
        ${json_schema_validator_SOURCE_DIR}/src
        ${reproc_SOURCE_DIR}/reproc++/include
        ${LIBNL_INCLUDE_DIRS}
        ${LIBSSH_INCLUDE_DIRS}
        ${radiotap_SOURCE_DIR}
        ${WIFI_HEADERS_DIR}
)

target_link_libraries(wpa3_deps INTERFACE
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

target_compile_definitions(wpa3_deps INTERFACE
        PROJECT_ROOT_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
)
target_precompile_headers(wpa3_deps INTERFACE
        <vector> <string> <map> <unordered_map> <set>
        <memory> <optional> <variant> <tuple> <functional>
        <algorithm> <numeric> <ranges>
        <fstream> <iostream> <filesystem>
        <chrono> <thread> <mutex> <atomic>
        <stdexcept> <cassert>
        <cstdint> <cstdlib> <cstring> <csignal>
        <sstream> <regex> <system_error>
        <nlohmann/json.hpp>
        <nlohmann/json-schema.hpp>
        <yaml-cpp/yaml.h>
        <tins/tins.h>
        <argparse/argparse.hpp>
        <reproc++/reproc.hpp>
)