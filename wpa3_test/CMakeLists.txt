cmake_minimum_required(VERSION 3.20)
cmake_policy(SET CMP0167 NEW)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
project(wpa3_tester VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
set(CMAKE_BUILD_RPATH_USE_ORIGIN TRUE)

get_property(dirs DIRECTORY ${CMAKE_SOURCE_DIR} PROPERTY LINK_DIRECTORIES)
foreach(dir ${dirs})
    list(APPEND CMAKE_INSTALL_RPATH ${dir})
endforeach()
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# --- VALGRIND / CTEST CONFIGURATION ---
find_program(MEMORYCHECK_COMMAND valgrind)
if (MEMORYCHECK_COMMAND)
    set(MEMORYCHECK_COMMAND_OPTIONS "--track-fds=yes --leak-check=full --error-exitcode=1 --show-leak-kinds=all")
    message(STATUS "Valgrind found: tracking FDs enabled for memcheck")
endif ()

# linker detection — applied after FetchContent to avoid contaminating try_compile checks
find_program(MOLD_EXE mold)
execute_process(COMMAND lld --version RESULT_VARIABLE LLD_FOUND OUTPUT_QUIET ERROR_QUIET)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-rpath,$ENV{LD_LIBRARY_PATH}")

find_program(CCACHE_PROGRAM ccache)
if (CCACHE_PROGRAM)
    set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
    message(STATUS "ccache found")
else ()
    message(STATUS "ccache not found")
endif ()

set(CMAKE_CXX_STANDARD 23)
option(ENABLE_COVERAGE "Enable coverage" OFF)

# compile with nice
if (UNIX)
    set(ENV{NINJA_STATUS} "[%f/%t %e] ")
endif ()

add_link_options(-fuse-ld=mold) #faster linker than lld
if (ENABLE_COVERAGE)
    add_compile_options(--coverage -O0 -g)
    add_link_options(--coverage)
endif ()

include(cmake/awk_files.cmake)
include(cmake/external_libs.cmake)

# Apply linker AFTER FetchContent — prevents try_compile checks in deps from being affected
if (MOLD_EXE)
    add_link_options("-fuse-ld=mold")
    message(STATUS "Using mold linker: ${MOLD_EXE}")
elseif (LLD_FOUND EQUAL 0)
    add_link_options("-fuse-ld=lld")
    message(STATUS "Using LLD linker")
endif ()

include(cmake/dependencies.cmake)
include(cmake/libraries.cmake)
include(cmake/targets.cmake)
include(cmake/coverage.cmake)

add_executable(${PROJECT_NAME}
        "../wpa3_test/main.cpp"
        include/config/Run_Config.h
)

target_link_libraries(${PROJECT_NAME} PRIVATE
        -Wl,--whole-archive wpa3_core -Wl,--no-whole-archive
        wpa3_deps
)

set_target_properties(${PROJECT_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if(ENABLE_COVERAGE)
    set_target_properties(${PROJECT_NAME} PROPERTIES EXCLUDE_FROM_ALL TRUE)
endif()

enable_testing()
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../tests" "${CMAKE_BINARY_DIR}/tests")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../tests_manual" "${CMAKE_BINARY_DIR}/tests_manual")
include(CPack)
