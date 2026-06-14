cmake_minimum_required(VERSION 3.20)
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

set_target_properties(result_overview PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Copy static assets to build/result_overview/ after build
add_custom_command(
    TARGET result_overview POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/result_overview"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/static"
        "${CMAKE_BINARY_DIR}/result_overview"
    COMMENT "Copying static assets -> build/result_overview/"
)
