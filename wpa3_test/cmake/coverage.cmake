if(NOT ENABLE_COVERAGE)
    return()
endif()

find_program(LCOV lcov REQUIRED)
find_program(GENHTML genhtml REQUIRED)

cmake_host_system_information(RESULT NPROC QUERY NUMBER_OF_LOGICAL_CORES)
math(EXPR NPROC "${NPROC} - 2")
if(NPROC LESS 1)
    set(NPROC 1)
endif()

set(COVERAGE_INFO      "${CMAKE_BINARY_DIR}/coverage.info")
set(COVERAGE_CLEAN     "${CMAKE_BINARY_DIR}/coverage_clean.info")
set(COVERAGE_REPORT    "${CMAKE_BINARY_DIR}/coverage_report")
set(COVERAGE_IGNORE    "inconsistent,range,negative,unused")

add_custom_target(coverage
    # reset counters
    COMMAND ${LCOV} --directory ${CMAKE_BINARY_DIR} --zerocounters

    # run tests
    COMMAND sudo -E ${CMAKE_CTEST_COMMAND}
            --test-dir ${CMAKE_BINARY_DIR}
            --output-on-failure

    # capture all coverage data
    COMMAND ${LCOV}
            --directory ${CMAKE_BINARY_DIR}
            --capture
            --output-file ${COVERAGE_INFO}
            --ignore-errors ${COVERAGE_IGNORE}
            --parallel ${NPROC}

    # keep only project sources — auto-excludes nix, gcc headers, _deps, etc.
    COMMAND ${LCOV}
            --extract ${COVERAGE_INFO}
            "${CMAKE_SOURCE_DIR}/*"
            --output-file ${COVERAGE_CLEAN}
            --ignore-errors ${COVERAGE_IGNORE}

    # generate HTML report
    COMMAND ${GENHTML}
            ${COVERAGE_CLEAN}
            --output-directory ${COVERAGE_REPORT}
            --ignore-errors ${COVERAGE_IGNORE}
            --parallel ${NPROC}

    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    USES_TERMINAL
    COMMENT "Coverage report -> ${COVERAGE_REPORT}/index.html"
)
