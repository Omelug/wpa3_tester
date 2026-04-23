cmake_minimum_required(VERSION 3.20)
cmake_policy(SET CMP0167 NEW)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
project(wpa3_tester VERSION 0.1.0 LANGUAGES C CXX)

# --- VALGRIND / CTEST CONFIGURATION ---
find_program(MEMORYCHECK_COMMAND valgrind)
if (MEMORYCHECK_COMMAND)
    set(MEMORYCHECK_COMMAND_OPTIONS "--track-fds=yes --leak-check=full --error-exitcode=1 --show-leak-kinds=all")
    message(STATUS "Valgrind found: tracking FDs enabled for memcheck")
endif ()

# optimization for compiling/ linking
execute_process(COMMAND lld --version RESULT_VARIABLE LLD_FOUND OUTPUT_QUIET ERROR_QUIET)
if (LLD_FOUND EQUAL 0)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=lld")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fuse-ld=lld")
    message(STATUS "Using LLD linker")
endif ()

find_program(CCACHE_PROGRAM ccache)
if (CCACHE_PROGRAM)
    set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
    message(STATUS "ccache found")
else ()
    message(STATUS "ccache not found")
endif ()

set(CMAKE_CXX_STANDARD 23)

option(ENABLE_COVERAGE "Enable coverage" OFF)

if (ENABLE_COVERAGE)
    add_compile_options(--coverage -O0 -g)
    add_link_options(--coverage)
endif ()

include(cmake/awk_files.cmake)
include(cmake/external_libs.cmake)
include(cmake/dependencies.cmake)
include(cmake/libraries.cmake)
include(cmake/targets.cmake)

add_executable(${PROJECT_NAME}
        "../wpa3_test/main.cpp"
)

target_link_libraries(${PROJECT_NAME} PRIVATE
        -Wl,--whole-archive wpa3_core -Wl,--no-whole-archive
        wpa3_deps
)

set_target_properties(${PROJECT_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

enable_testing()
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../tests" "${CMAKE_BINARY_DIR}/tests")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../tests_manual" "${CMAKE_BINARY_DIR}/tests_manual")
include(CPack)
