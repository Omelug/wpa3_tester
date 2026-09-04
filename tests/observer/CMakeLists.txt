file(COPY test_tshark_minimal.pcapng beacon_test.pcapng DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY iperf3_real DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_doctest_exe(run_observer_tests SOURCES test_tshark.cpp TEST_NAME ObserverTests)
target_compile_definitions(run_observer_tests PRIVATE
        TEST_PCAP_DIR="."
)

add_doctest_exe(run_iperf_tests SOURCES test_iperf.cpp TEST_NAME IperfTests)
