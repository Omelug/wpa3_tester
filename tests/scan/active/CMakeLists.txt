set(SCAN_LIBS test_helpers tins)

add_doctest_exe(run_scan_active_tests SOURCES test_handle_beacon.cpp TEST_NAME ScanActiveTests LIBS ${SCAN_LIBS})