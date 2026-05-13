add_executable(test_manual_injection_two_iface "test_manual_injection_two_iface.cpp")
target_link_libraries(test_manual_injection_two_iface PRIVATE manual_test_core)
set_target_properties(test_manual_injection_two_iface PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/manual_tests/two_iface"
)
