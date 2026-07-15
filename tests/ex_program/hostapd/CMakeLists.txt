file(COPY mana_handshakes.hccapx captured_hashes.txt DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_doctest_exe(run_hostapd_tests SOURCES test_hostapd_helper.cpp TEST_NAME HostapdHelperTests)
target_compile_definitions(run_hostapd_tests PRIVATE TEST_DATA_DIR=".")
