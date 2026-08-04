file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/../../test_data DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

set(MC_MITM_LIBS test_helpers tins)

add_doctest_exe(run_mc_mitm_tests SOURCES test_mc_mitm.cpp TEST_NAME McMitmTests LIBS ${MC_MITM_LIBS})
add_doctest_exe(run_monitor_socket_tests SOURCES test_MonitorSocket.cpp TEST_NAME RunMonitorSocketTests LIBS ${MC_MITM_LIBS})
add_doctest_exe(run_wifi_utils SOURCES test_wifi_utils.cpp TEST_NAME WiFiUtilsTests LIBS ${MC_MITM_LIBS})
add_doctest_exe(run_real_channel_tests SOURCES test_real_channel.cpp TEST_NAME RealChannelTests LIBS ${MC_MITM_LIBS})
add_doctest_exe(run_rogue_channel_tests SOURCES test_rogue_channel.cpp TEST_NAME RogueChannelTests LIBS ${MC_MITM_LIBS})
