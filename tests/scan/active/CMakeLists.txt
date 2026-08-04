file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/../../test_data DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

set(SCAN_LIBS test_helpers tins)

add_doctest_exe(run_scan_active_tests SOURCES test_handle_beacon.cpp TEST_NAME ScanActiveTests LIBS ${SCAN_LIBS})