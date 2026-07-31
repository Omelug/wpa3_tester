file(COPY config_validation DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY config_validation DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_doctest_exe(run_validation_tests SOURCES test_config_validation.cpp TEST_NAME ValidationTests)
target_compile_definitions(run_validation_tests PRIVATE
        TEST_DATA_DIR="config_validation"
)

add_doctest_exe(run_cleanup_tests SOURCES test_cleanup_namespaces.cpp TEST_NAME CleanupTests)
add_doctest_exe(run_scan_tests SOURCES test_scan.cpp TEST_NAME ScanTests)
