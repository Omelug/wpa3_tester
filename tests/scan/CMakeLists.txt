file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/../test_data DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

set(SCAN_LIBS test_helpers tins)

add_doctest_exe(run_scan_solve_new_pdu_tests SOURCES test_solve_new_pdu.cpp TEST_NAME ScanSolveNewPduTests LIBS ${SCAN_LIBS})
add_doctest_exe(run_scan_channel_tests SOURCES test_get_external_bb_channels.cpp TEST_NAME ScanChannelTests LIBS ${SCAN_LIBS})
add_doctest_exe(run_scan_list_tests SOURCES test_scan_list.cpp TEST_NAME ScanListTests LIBS ${SCAN_LIBS})
add_doctest_exe(run_scan_process_packet_tests SOURCES test_process_single_packet.cpp TEST_NAME ScanProcessPacketTests LIBS ${SCAN_LIBS})
