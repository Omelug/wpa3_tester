file(COPY config_validation DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
     PATTERN "run_out" EXCLUDE)
# Validator schemas are referenced from test YAMLs via relative paths that resolve
# to <build_root>/wpa3_test/attack_config/validator/ — copy them there.
file(COPY ${CMAKE_SOURCE_DIR}/attack_config/validator/
     DESTINATION ${CMAKE_BINARY_DIR}/wpa3_test/attack_config/validator/)

add_doctest_exe(run_validation_tests SOURCES test_config_validation.cpp TEST_NAME ValidationTests)
target_compile_definitions(run_validation_tests PRIVATE
        TEST_DATA_DIR="config_validation"
)

add_doctest_exe(run_cleanup_tests SOURCES test_cleanup_namespaces.cpp TEST_NAME CleanupTests)
add_doctest_exe(run_scan_tests SOURCES test_scan.cpp TEST_NAME ScanTests)
