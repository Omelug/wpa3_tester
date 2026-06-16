cmake_minimum_required(VERSION 3.20)
project(wpa3_tester)

include(cmake/awk_files.cmake)
include(cmake/external_libs.cmake)

# mold/lld: applied AFTER FetchContent to avoid contaminating try_compile checks in deps
find_program(MOLD_EXE mold)
execute_process(COMMAND lld --version RESULT_VARIABLE LLD_FOUND OUTPUT_QUIET ERROR_QUIET)
if(DEFINED ENV{LD_LIBRARY_PATH} AND NOT "$ENV{LD_LIBRARY_PATH}" STREQUAL "")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-rpath,$ENV{LD_LIBRARY_PATH}")
endif()
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

set(HOSTAPD_EXTRA_CFLAGS "")
if(EXISTS "/etc/nixos")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OPENSSL REQUIRED openssl)
    pkg_check_modules(DBUS dbus-1)
    set(HOSTAPD_EXTRA_CFLAGS "${OPENSSL_CFLAGS}")
    if(DBUS_FOUND)
        string(APPEND HOSTAPD_EXTRA_CFLAGS " ${DBUS_CFLAGS}")
    endif()
    string(REPLACE ";" " " HOSTAPD_EXTRA_CFLAGS "${HOSTAPD_EXTRA_CFLAGS}")
    message(STATUS "NixOS:  OPENSSL_CFLAGS = ${OPENSSL_CFLAGS}")
else()
    message(STATUS "Standard Linux (Debian/Ubuntu). Not changes in include paths")
endif()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/hostapd_cflags.h.in"
    "${CMAKE_BINARY_DIR}/generated/hostapd_cflags.h"
)
target_include_directories(wpa3_ex_program PRIVATE "${CMAKE_BINARY_DIR}/generated")

add_executable(${PROJECT_NAME}
        "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp"
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

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../tests"         "${CMAKE_BINARY_DIR}/tests")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../tests_manual"  "${CMAKE_BINARY_DIR}/tests_manual")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../result_overview" "${CMAKE_BINARY_DIR}/result_overview_build")
include(CPack)