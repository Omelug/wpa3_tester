# copy pcap files for tests
add_custom_target(copy_pcap_files
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/pcap
        ${CMAKE_CURRENT_BINARY_DIR}/pcap
        COMMENT "Copying pcap to build directory"
)

set(MC_MITM_LIBS test_helpers tins)

add_doctest_exe(run_mc_mitm_tests SOURCES test_mc_mitm.cpp TEST_NAME McMitmTests LIBS ${MC_MITM_LIBS})
add_doctest_exe(run_monitor_socket_tests SOURCES test_MonitorSocket.cpp TEST_NAME RunMonitorSocketTests LIBS ${MC_MITM_LIBS})
add_doctest_exe(run_wifi_utils SOURCES test_wifi_utils.cpp TEST_NAME WiFiUtilsTests LIBS ${MC_MITM_LIBS})
add_doctest_exe(run_real_channel_tests SOURCES test_real_channel.cpp TEST_NAME RealChannelTests LIBS ${MC_MITM_LIBS})
add_doctest_exe(run_rogue_channel_tests SOURCES test_rogue_channel.cpp TEST_NAME RogueChannelTests LIBS ${MC_MITM_LIBS})
add_doctest_exe(run_scan_active_tests SOURCES test_scan_active.cpp TEST_NAME ScanActiveTests LIBS ${MC_MITM_LIBS})

foreach (t run_mc_mitm_tests run_monitor_socket_tests run_wifi_utils run_real_channel_tests run_rogue_channel_tests run_scan_active_tests)
    add_dependencies(${t} copy_pcap_files)
endforeach ()
