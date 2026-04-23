# Manual test_manual_iface
add_executable(test_manual_iface "manual_iface_tests.cpp")
target_link_libraries(test_manual_iface PRIVATE manual_test_core test_helpers)
set_target_properties(test_manual_iface PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/manual_tests/system"
)