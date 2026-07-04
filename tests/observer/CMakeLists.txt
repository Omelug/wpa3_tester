add_doctest_exe(run_observer_tests SOURCES test_tshark.cpp TEST_NAME ObserverTests)
target_compile_definitions(run_observer_tests PRIVATE
        TEST_PCAP_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
)
