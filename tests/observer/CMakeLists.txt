# observer tests
add_executable(run_observer_tests test_tshark.cpp)

target_link_libraries(run_observer_tests PRIVATE
        wpa3_core
        doctest_headers
)

target_compile_definitions(run_observer_tests PRIVATE
        TEST_PCAP_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
)

add_test(NAME ObserverTests COMMAND run_observer_tests)
