add_executable(test_config_validation "manual_config_validation.cpp")
target_link_libraries(test_config_validation PRIVATE manual_test_core)
set_target_properties(test_config_validation PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/manual_tests/config"
)
