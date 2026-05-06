add_executable(test_manual_iface_info "test_manual_iface_info.cpp")
target_link_libraries(test_manual_iface_info PRIVATE manual_test_core)
set_target_properties(test_manual_iface_info PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/manual_tests/attacks"
)