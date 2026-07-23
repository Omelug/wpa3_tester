file(COPY mana_handshakes.hccapx captured_hashes.txt ap_sae_akm.log DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_doctest_exe(run_hostapd_tests SOURCES test_hostapd_helper.cpp TEST_NAME HostapdHelperTests)
target_compile_definitions(run_hostapd_tests PRIVATE TEST_DATA_DIR=".")

add_doctest_exe(run_wpa_overrides_tests SOURCES test_wpa_overrides.cpp TEST_NAME WpaOverridesTests)
