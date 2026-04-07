

# Manual channel switch test
add_executable(test_manual_channel_switch "manual_channel_switch.cpp")
target_link_libraries(test_manual_channel_switch PRIVATE manual_test_core)
set_target_properties(test_manual_channel_switch PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin/manual_tests/attacks"
)

# Manual get commit values test
add_executable(test_manual_get_commit_values "manual_get_commit_values.cpp")
target_link_libraries(test_manual_get_commit_values PRIVATE manual_test_core)
set_target_properties(test_manual_get_commit_values PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin/manual_tests/attacks"
)

# Manual MC-MitM test
add_executable(test_manual_mc_mitm "manual_mc_mitm.cpp")
target_link_libraries(test_manual_mc_mitm PRIVATE manual_test_core)
set_target_properties(test_manual_mc_mitm PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin/manual_tests/attacks"
)
