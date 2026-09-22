cmake_minimum_required(VERSION 3.20)

# Download Wireshark manuf DB once at configure time
set(MANUF_FILE "${CMAKE_CURRENT_SOURCE_DIR}/static/manuf")
if (NOT EXISTS "${MANUF_FILE}")
    message(STATUS "Downloading Wireshark manuf database...")
    file(DOWNLOAD
            "https://www.wireshark.org/download/automated/data/manuf"
            "${MANUF_FILE}"
            STATUS _manuf_status
            TLS_VERIFY ON
    )
    list(GET _manuf_status 0 _manuf_code)
    if (NOT _manuf_code EQUAL 0)
        message(WARNING "manuf download failed - vendor lookup will return empty strings")
        file(WRITE "${MANUF_FILE}" "")
    endif ()
endif ()

file(GLOB_RECURSE RESULT_OVERVIEW_SOURCES CONFIGURE_DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
)

add_executable(result_overview ${RESULT_OVERVIEW_SOURCES})

target_include_directories(result_overview PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../wpa3_test/include
)


target_link_libraries(result_overview PRIVATE
        -Wl,--whole-archive wpa3_core -Wl,--no-whole-archive
        wpa3_deps
        yaml-cpp
)

target_compile_definitions(result_overview PRIVATE MANUF_FILE_PATH="${MANUF_FILE}")

set_target_properties(result_overview PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED ON
)

# Copy static assets and test data to build/result_overview/ after build
add_custom_command(
        TARGET result_overview POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/result_overview"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/static"
        "${CMAKE_BINARY_DIR}/result_overview"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/src/observer/observers_test_data"
        "${CMAKE_BINARY_DIR}/result_overview/observers_test_data"
        COMMENT "Copying static assets and test data -> build/result_overview/"
)

target_compile_definitions(result_overview PRIVATE
        OBSERVERS_TEST_DATA="${CMAKE_BINARY_DIR}/result_overview/observers_test_data"
)
