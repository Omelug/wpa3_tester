# copy pcap files for tests
add_custom_target(copy_pcap_files
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/pcap
        ${CMAKE_CURRENT_BINARY_DIR}/pcap
        COMMENT "Copying pcap to build directory"
)

# mc_mitm attack tests
add_executable(run_mc_mitm_tests test_mc_mitm.cpp)

target_link_libraries(run_mc_mitm_tests PRIVATE
        test_helpers
        wpa3_core
        doctest_headers
        tins
)

add_dependencies(run_mc_mitm_tests copy_pcap_files)
add_test(NAME McMitmTests COMMAND run_mc_mitm_tests)

# MonitorSocket
add_executable(run_monitor_socket_tests test_MonitorSocket.cpp)

target_link_libraries(run_monitor_socket_tests PRIVATE
        test_helpers
        wpa3_core
        doctest_headers
        tins
)

add_dependencies(run_monitor_socket_tests copy_pcap_files)
add_test(NAME RunMonitorSocketTests COMMAND run_monitor_socket_tests)

# wifi utils
add_executable(run_wifi_utils test_wifi_utils.cpp)

target_link_libraries(run_wifi_utils PRIVATE
        test_helpers
        wpa3_core
        doctest_headers
        tins
)

add_dependencies(run_wifi_utils copy_pcap_files)
add_test(NAME WiFiUtilsTests COMMAND run_wifi_utils)

# run_real_channel_tests
add_executable(run_real_channel_tests test_real_channel.cpp)

target_link_libraries(run_real_channel_tests PRIVATE
        test_helpers
        wpa3_core
        doctest_headers
        tins
)

add_dependencies(run_real_channel_tests copy_pcap_files)
add_test(NAME RealChannelTests COMMAND run_real_channel_tests)

# run_rogue_channel_tests
add_executable(run_rogue_channel_tests test_rogue_channel.cpp)

target_link_libraries(run_rogue_channel_tests PRIVATE
        test_helpers
        wpa3_core
        doctest_headers
        tins
)
add_dependencies(run_rogue_channel_tests copy_pcap_files)
add_test(NAME RogueChannelTests COMMAND run_rogue_channel_tests)
