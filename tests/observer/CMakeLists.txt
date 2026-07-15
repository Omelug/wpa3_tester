file(COPY test_tshark_minimal.pcapng DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_doctest_exe(run_observer_tests SOURCES test_tshark.cpp TEST_NAME ObserverTests)
target_compile_definitions(run_observer_tests PRIVATE
        TEST_PCAP_DIR="."
)
