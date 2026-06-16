# hw_cap_tests
add_executable(hw_cap_tests test_hw_capabilities.cpp)
target_link_libraries(hw_cap_tests PRIVATE
        wpa3_core
        doctest_headers
)
add_test(NAME HWCapabilitiesTests COMMAND hw_cap_tests)

add_executable(run_pdu_solve_tests test_solve_new_pdu.cpp)
target_link_libraries(run_pdu_solve_tests PRIVATE
        wpa3_core
        doctest_headers
)
add_test(NAME SolveNewPduTests COMMAND run_pdu_solve_tests)

# system tests
add_executable(run_system_tests test_process_manager.cpp)
target_link_libraries(run_system_tests PRIVATE
        wpa3_core
        doctest_headers
)
add_test(NAME SystemTests COMMAND run_system_tests)

# validator tests
add_executable(run_validator_tests test_validator.cpp)
target_link_libraries(run_validator_tests PRIVATE
        wpa3_core
        doctest_headers
)
add_test(NAME YAMLValidatorTests COMMAND run_validator_tests)

# ProcessManager  callbacks
add_executable(run_callback_tests test_ProcessManager_callbacks.cpp)
target_link_libraries(run_callback_tests PRIVATE
        wpa3_core
        doctest_headers
)
add_test(NAME PMCallbackTests COMMAND run_callback_tests)

# ath9k_htc firmware tests
add_executable(run_ath9k_htc_tests test_ath9k_htc.cpp)
target_link_libraries(run_ath9k_htc_tests PRIVATE
        wpa3_core
        doctest_headers
)
add_test(NAME Ath9kHtcTests COMMAND run_ath9k_htc_tests)

# utils tests
add_executable(run_utils_tests test_utils.cpp)
target_link_libraries(run_utils_tests PRIVATE
        wpa3_core
        doctest_headers
)
add_test(NAME UtilsTests COMMAND run_utils_tests)

add_executable(run_ip_tests test_ip.cpp)
target_link_libraries(run_ip_tests PRIVATE
        wpa3_core
        doctest_headers
)
add_test(NAME IpTests COMMAND run_ip_tests)

add_subdirectory(hw_info)