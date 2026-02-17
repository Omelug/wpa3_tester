add_executable(run_validation_tests test_config_validation.cpp)

target_link_libraries(run_validation_tests PRIVATE
        wpa3_core
        doctest_headers
)

target_compile_definitions(run_validation_tests PRIVATE
        TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/config_validation"
)

add_test(NAME ValidationTests COMMAND run_validation_tests)